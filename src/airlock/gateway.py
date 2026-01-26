"""Access Gateway Daemon — Routes authenticated requests to services.

This daemon:
- Listens on Unix socket for client requests
- Validates tokens with the TOTP verifier
- Routes operations to service connectors
- Enforces read-only permissions
- Logs all operations
- Runs as isolated user 'airlock-gateway'
"""

import asyncio
import json
import logging
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Protocol

logger = logging.getLogger(__name__)


def utcnow() -> datetime:
    """Get current UTC time (naive for consistency with tokens)."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


@dataclass
class GatewayConfig:
    """Gateway configuration."""
    socket_path: Path = field(default_factory=lambda: Path("/run/airlock/gateway.sock"))
    totp_socket_path: Path = field(default_factory=lambda: Path("/run/airlock/totp.sock"))
    audit_log_path: Path = field(default_factory=lambda: Path("/var/log/airlock/audit.jsonl"))
    credentials_path: Path = field(default_factory=lambda: Path("/var/lib/airlock/credentials"))


class ServiceConnector(Protocol):
    """Protocol for service connectors."""
    
    @property
    def service_name(self) -> str:
        """Service identifier (e.g., 'gmail')."""
        ...
    
    async def execute(
        self,
        operation: str,
        params: dict[str, Any],
    ) -> Any:
        """Execute a read-only operation."""
        ...
    
    def list_operations(self) -> list[str]:
        """List available operations."""
        ...


class AuditLogger:
    """Append-only audit log."""
    
    def __init__(self, path: Path):
        self.path = path
        self._ensure_dir()
    
    def _ensure_dir(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
    
    def log(
        self,
        event: str,
        token_id: str | None = None,
        service: str | None = None,
        operation: str | None = None,
        params: dict[str, Any] | None = None,
        result: str | None = None,
        error: str | None = None,
        **extra: Any,
    ) -> None:
        """Write an audit entry."""
        entry = {
            "ts": utcnow().isoformat() + "Z",
            "event": event,
        }
        if token_id:
            entry["token_id"] = token_id
        if service:
            entry["service"] = service
        if operation:
            entry["operation"] = operation
        if params:
            # Sanitize params (remove sensitive data)
            entry["params"] = {k: v for k, v in params.items() if not k.startswith("_")}
        if result:
            entry["result"] = result
        if error:
            entry["error"] = error
        entry.update(extra)
        
        with open(self.path, "a") as f:
            f.write(json.dumps(entry) + "\n")
        
        logger.debug(f"Audit: {event} service={service} op={operation}")


class TOTPVerifierClient:
    """Client for communicating with the TOTP verifier daemon."""
    
    def __init__(self, socket_path: Path):
        self.socket_path = socket_path
    
    async def _send(self, request: dict[str, Any]) -> dict[str, Any]:
        """Send a request to the TOTP verifier."""
        reader, writer = await asyncio.open_unix_connection(str(self.socket_path))
        
        try:
            writer.write(json.dumps(request).encode())
            await writer.drain()
            
            data = await reader.read(4096)
            return json.loads(data.decode())
        finally:
            writer.close()
            await writer.wait_closed()
    
    async def request_access(
        self,
        services: list[str],
        reason: str,
        ttl_minutes: int = 60,
    ) -> str:
        """Request access to services. Returns request_id."""
        response = await self._send({
            "action": "request_access",
            "services": services,
            "reason": reason,
            "ttl_minutes": ttl_minutes,
        })
        
        if "error" in response:
            raise RuntimeError(response["error"])
        
        return response["request_id"]
    
    async def verify(self, request_id: str, totp_code: str) -> dict[str, Any] | None:
        """Verify TOTP and get token. Returns token dict or None."""
        response = await self._send({
            "action": "verify",
            "request_id": request_id,
            "totp_code": totp_code,
        })
        
        if "error" in response:
            return None
        
        return response.get("token")
    
    async def validate(self, token_id: str, service: str) -> bool:
        """Check if a token is valid for a service."""
        response = await self._send({
            "action": "validate",
            "token_id": token_id,
            "service": service,
        })
        return response.get("valid", False)
    
    async def revoke(self, token_id: str) -> bool:
        """Revoke a token."""
        response = await self._send({
            "action": "revoke",
            "token_id": token_id,
        })
        return response.get("revoked", False)
    
    async def ping(self) -> bool:
        """Check if verifier is running."""
        try:
            response = await self._send({"action": "ping"})
            return response.get("status") == "ok"
        except Exception:
            return False


class AccessGateway:
    """Access Gateway Daemon.
    
    Handles client requests, validates tokens, and routes to connectors.
    """
    
    def __init__(self, config: GatewayConfig):
        self.config = config
        self.verifier = TOTPVerifierClient(config.totp_socket_path)
        self.audit = AuditLogger(config.audit_log_path)
        self._connectors: dict[str, ServiceConnector] = {}
        self._server: asyncio.Server | None = None
    
    def register_connector(self, connector: ServiceConnector) -> None:
        """Register a service connector."""
        self._connectors[connector.service_name] = connector
        logger.info(f"Registered connector: {connector.service_name}")
    
    async def _handle_request_access(
        self,
        services: list[str],
        reason: str,
        ttl_minutes: int = 60,
    ) -> dict[str, Any]:
        """Handle access request from client."""
        # Validate requested services exist
        unknown = [s for s in services if s not in self._connectors]
        if unknown:
            return {"error": f"Unknown services: {unknown}"}
        
        self.audit.log(
            "access_requested",
            service=",".join(services),
            reason=reason,
        )
        
        try:
            request_id = await self.verifier.request_access(services, reason, ttl_minutes)
            return {"request_id": request_id}
        except Exception as e:
            self.audit.log("access_request_failed", error=str(e))
            return {"error": str(e)}
    
    async def _handle_verify(
        self,
        request_id: str,
        totp_code: str,
    ) -> dict[str, Any]:
        """Handle TOTP verification."""
        token = await self.verifier.verify(request_id, totp_code)
        
        if token:
            self.audit.log(
                "token_issued",
                token_id=token["token_id"],
                service=",".join(token["services"]),
            )
            return {"token": token}
        else:
            self.audit.log(
                "verification_failed",
                request_id=request_id,
            )
            return {"error": "Verification failed"}
    
    async def _handle_execute(
        self,
        token_id: str,
        service: str,
        operation: str,
        params: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Handle service operation execution."""
        params = params or {}
        
        # Validate token
        if not await self.verifier.validate(token_id, service):
            self.audit.log(
                "operation_denied",
                token_id=token_id,
                service=service,
                operation=operation,
                error="Invalid or expired token",
            )
            return {"error": "Invalid or expired token"}
        
        # Get connector
        connector = self._connectors.get(service)
        if not connector:
            return {"error": f"Unknown service: {service}"}
        
        # Check operation exists
        if operation not in connector.list_operations():
            self.audit.log(
                "operation_denied",
                token_id=token_id,
                service=service,
                operation=operation,
                error="Unknown operation",
            )
            return {"error": f"Unknown operation: {operation}"}
        
        # Execute
        try:
            self.audit.log(
                "operation_started",
                token_id=token_id,
                service=service,
                operation=operation,
                params=params,
            )
            
            result = await connector.execute(operation, params)
            
            self.audit.log(
                "operation_completed",
                token_id=token_id,
                service=service,
                operation=operation,
                result="success",
            )
            
            return {"result": result}
        
        except Exception as e:
            self.audit.log(
                "operation_failed",
                token_id=token_id,
                service=service,
                operation=operation,
                error=str(e),
            )
            return {"error": str(e)}
    
    async def _handle_revoke(self, token_id: str) -> dict[str, Any]:
        """Handle token revocation."""
        revoked = await self.verifier.revoke(token_id)
        
        if revoked:
            self.audit.log("token_revoked", token_id=token_id)
        
        return {"revoked": revoked}
    
    async def _handle_list_services(self) -> dict[str, Any]:
        """List available services and their operations."""
        services = {}
        for name, connector in self._connectors.items():
            services[name] = {
                "operations": connector.list_operations(),
            }
        return {"services": services}
    
    async def _handle_client(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        """Handle a client connection."""
        try:
            data = await reader.read(8192)
            if not data:
                return
            
            try:
                request = json.loads(data.decode())
            except json.JSONDecodeError:
                response = {"error": "Invalid JSON"}
                writer.write(json.dumps(response).encode())
                await writer.drain()
                return
            
            action = request.get("action")
            response: dict[str, Any]
            
            if action == "request_access":
                response = await self._handle_request_access(
                    services=request.get("services", []),
                    reason=request.get("reason", ""),
                    ttl_minutes=request.get("ttl_minutes", 60),
                )
            
            elif action == "verify":
                response = await self._handle_verify(
                    request_id=request.get("request_id", ""),
                    totp_code=request.get("totp_code", ""),
                )
            
            elif action == "execute":
                response = await self._handle_execute(
                    token_id=request.get("token_id", ""),
                    service=request.get("service", ""),
                    operation=request.get("operation", ""),
                    params=request.get("params"),
                )
            
            elif action == "revoke":
                response = await self._handle_revoke(
                    token_id=request.get("token_id", ""),
                )
            
            elif action == "list_services":
                response = await self._handle_list_services()
            
            elif action == "ping":
                verifier_ok = await self.verifier.ping()
                response = {
                    "status": "ok",
                    "verifier": "ok" if verifier_ok else "unavailable",
                    "services": list(self._connectors.keys()),
                }
            
            else:
                response = {"error": f"Unknown action: {action}"}
            
            writer.write(json.dumps(response).encode())
            await writer.drain()
        
        except Exception as e:
            logger.exception("Error handling client")
            try:
                writer.write(json.dumps({"error": str(e)}).encode())
                await writer.drain()
            except Exception:
                pass
        
        finally:
            writer.close()
            await writer.wait_closed()
    
    async def start(self) -> None:
        """Start the gateway daemon."""
        # Ensure socket directory
        socket_path = self.config.socket_path
        socket_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Remove stale socket
        if socket_path.exists():
            socket_path.unlink()
        
        # Start server
        self._server = await asyncio.start_unix_server(
            self._handle_client,
            path=str(socket_path),
        )
        
        # Set socket permissions (agent user can connect)
        os.chmod(socket_path, 0o660)
        
        logger.info(f"Gateway listening on {socket_path}")
        self.audit.log("gateway_started")
        
        async with self._server:
            await self._server.serve_forever()
    
    async def stop(self) -> None:
        """Stop the daemon."""
        if self._server:
            self._server.close()
            await self._server.wait_closed()
            self.audit.log("gateway_stopped")


async def main():
    """Run the gateway daemon."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Airlock Access Gateway")
    parser.add_argument(
        "--socket",
        default="/run/airlock/gateway.sock",
        help="Unix socket path",
    )
    parser.add_argument(
        "--totp-socket",
        default="/run/airlock/totp.sock",
        help="TOTP verifier socket path",
    )
    parser.add_argument(
        "--audit-log",
        default="/var/log/airlock/audit.jsonl",
        help="Audit log path",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug logging",
    )
    args = parser.parse_args()
    
    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )
    
    config = GatewayConfig(
        socket_path=Path(args.socket),
        totp_socket_path=Path(args.totp_socket),
        audit_log_path=Path(args.audit_log),
    )
    
    gateway = AccessGateway(config)
    
    # TODO: Load and register connectors from config
    
    try:
        await gateway.start()
    except KeyboardInterrupt:
        logger.info("Shutting down...")
        await gateway.stop()


if __name__ == "__main__":
    asyncio.run(main())
