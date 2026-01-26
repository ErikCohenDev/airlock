"""Tests for Access Gateway."""

import json
import tempfile
from pathlib import Path
from typing import Any

import pytest

from airlock.gateway import (
    AccessGateway,
    AuditLogger,
    GatewayConfig,
    ServiceConnector,
)


class MockConnector:
    """Mock service connector for testing."""
    
    def __init__(self, name: str = "mock"):
        self._name = name
        self._operations = ["list_items", "get_item", "search"]
        self._data = {"items": [{"id": 1, "name": "test"}]}
    
    @property
    def service_name(self) -> str:
        return self._name
    
    async def execute(self, operation: str, params: dict[str, Any]) -> Any:
        if operation == "list_items":
            return self._data["items"]
        elif operation == "get_item":
            item_id = params.get("id")
            for item in self._data["items"]:
                if item["id"] == item_id:
                    return item
            return None
        elif operation == "search":
            query = params.get("query", "")
            return [i for i in self._data["items"] if query in i.get("name", "")]
        elif operation == "fail":
            raise RuntimeError("Intentional failure")
        else:
            raise ValueError(f"Unknown operation: {operation}")
    
    def list_operations(self) -> list[str]:
        return self._operations


class TestAuditLogger:
    """Test audit logging."""
    
    @pytest.fixture
    def temp_dir(self):
        with tempfile.TemporaryDirectory() as d:
            yield Path(d)
    
    def test_creates_log_file(self, temp_dir):
        log_path = temp_dir / "audit.jsonl"
        logger = AuditLogger(log_path)
        
        logger.log("test_event", service="gmail")
        
        assert log_path.exists()
    
    def test_appends_json_lines(self, temp_dir):
        log_path = temp_dir / "audit.jsonl"
        logger = AuditLogger(log_path)
        
        logger.log("event1")
        logger.log("event2")
        logger.log("event3")
        
        lines = log_path.read_text().strip().split("\n")
        assert len(lines) == 3
        
        for line in lines:
            entry = json.loads(line)
            assert "ts" in entry
            assert "event" in entry
    
    def test_includes_all_fields(self, temp_dir):
        log_path = temp_dir / "audit.jsonl"
        logger = AuditLogger(log_path)
        
        logger.log(
            "operation_completed",
            token_id="tok_123",
            service="gmail",
            operation="list_messages",
            params={"limit": 10},
            result="success",
        )
        
        entry = json.loads(log_path.read_text().strip())
        assert entry["event"] == "operation_completed"
        assert entry["token_id"] == "tok_123"
        assert entry["service"] == "gmail"
        assert entry["operation"] == "list_messages"
        assert entry["params"] == {"limit": 10}
        assert entry["result"] == "success"
    
    def test_sanitizes_private_params(self, temp_dir):
        log_path = temp_dir / "audit.jsonl"
        logger = AuditLogger(log_path)
        
        logger.log(
            "test",
            params={"query": "visible", "_secret": "hidden"},
        )
        
        entry = json.loads(log_path.read_text().strip())
        assert entry["params"] == {"query": "visible"}
        assert "_secret" not in entry["params"]


class TestAccessGateway:
    """Test gateway logic (without socket communication)."""
    
    @pytest.fixture
    def temp_dir(self):
        with tempfile.TemporaryDirectory() as d:
            yield Path(d)
    
    @pytest.fixture
    def config(self, temp_dir):
        return GatewayConfig(
            socket_path=temp_dir / "gateway.sock",
            totp_socket_path=temp_dir / "totp.sock",
            audit_log_path=temp_dir / "audit.jsonl",
        )
    
    @pytest.fixture
    def gateway(self, config):
        return AccessGateway(config)
    
    def test_register_connector(self, gateway):
        connector = MockConnector("gmail")
        gateway.register_connector(connector)
        
        assert "gmail" in gateway._connectors
        assert gateway._connectors["gmail"] is connector
    
    @pytest.mark.asyncio
    async def test_list_services(self, gateway):
        gateway.register_connector(MockConnector("gmail"))
        gateway.register_connector(MockConnector("calendar"))
        
        response = await gateway._handle_list_services()
        
        assert "services" in response
        assert "gmail" in response["services"]
        assert "calendar" in response["services"]
        assert "list_items" in response["services"]["gmail"]["operations"]
    
    @pytest.mark.asyncio
    async def test_request_access_unknown_service(self, gateway):
        response = await gateway._handle_request_access(
            services=["nonexistent"],
            reason="test",
        )
        
        assert "error" in response
        assert "nonexistent" in response["error"]
    
    @pytest.mark.asyncio
    async def test_execute_logs_denied_operation(self, gateway, temp_dir):
        """Execute creates audit entries when token validation fails."""
        gateway.register_connector(MockConnector("gmail"))
        
        # Mock verifier to reject token
        async def mock_validate(token_id, service):
            return False
        gateway.verifier.validate = mock_validate
        
        # Execute with invalid token
        response = await gateway._handle_execute(
            token_id="invalid_token",
            service="gmail",
            operation="list_items",
        )
        
        assert "error" in response
        
        # Check audit log was created
        audit_log = temp_dir / "audit.jsonl"
        assert audit_log.exists()
        
        content = audit_log.read_text()
        assert "operation_denied" in content
    
    @pytest.mark.asyncio
    async def test_execute_success(self, gateway, temp_dir):
        """Execute succeeds with valid token."""
        connector = MockConnector("gmail")
        gateway.register_connector(connector)
        
        # Mock verifier to accept token
        async def mock_validate(token_id, service):
            return True
        gateway.verifier.validate = mock_validate
        
        response = await gateway._handle_execute(
            token_id="tok_valid",
            service="gmail",
            operation="list_items",
            params={},
        )
        
        assert "result" in response
        assert response["result"] == [{"id": 1, "name": "test"}]
        
        # Check audit log
        audit_log = temp_dir / "audit.jsonl"
        content = audit_log.read_text()
        assert "operation_started" in content
        assert "operation_completed" in content
    
    @pytest.mark.asyncio
    async def test_execute_unknown_operation(self, gateway):
        """Unknown operation is rejected."""
        gateway.register_connector(MockConnector("gmail"))
        
        # Mock token validation to return True
        async def mock_validate(token_id, service):
            return True
        gateway.verifier.validate = mock_validate
        
        response = await gateway._handle_execute(
            token_id="tok_valid",
            service="gmail",
            operation="unknown_op",
        )
        
        assert "error" in response
        assert "Unknown operation" in response["error"]
