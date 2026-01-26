"""Airlock CLI — Command-line interface for setup and management."""

import json
import os
import subprocess
import sys
from datetime import datetime
from pathlib import Path

import typer
import yaml
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from airlock.totp_verifier import TOTPConfig, TOTPGenerator

app = typer.Typer(
    name="airlock",
    help="Secure Access Gateway — Human-in-the-loop access control for AI agents",
)
console = Console()

# Default paths
DEFAULT_CONFIG_DIR = Path.home() / ".config" / "airlock"
DEFAULT_DATA_DIR = Path.home() / ".local" / "share" / "airlock"
DEFAULT_LOG_DIR = Path.home() / ".local" / "share" / "airlock" / "logs"
DEFAULT_RUN_DIR = Path("/run/airlock") if os.geteuid() == 0 else Path.home() / ".local" / "run" / "airlock"


def get_config_path() -> Path:
    return DEFAULT_CONFIG_DIR / "config.yaml"


def load_config() -> dict:
    """Load config from file."""
    config_path = get_config_path()
    if config_path.exists():
        return yaml.safe_load(config_path.read_text()) or {}
    return {}


def save_config(config: dict) -> None:
    """Save config to file."""
    config_path = get_config_path()
    config_path.parent.mkdir(parents=True, exist_ok=True)
    config_path.write_text(yaml.dump(config, default_flow_style=False))


@app.command()
def init():
    """Initialize Airlock configuration."""
    console.print("[bold]Airlock Initialization[/bold]\n")
    
    config_path = get_config_path()
    if config_path.exists():
        if not typer.confirm("Config already exists. Overwrite?"):
            raise typer.Abort()
    
    # Create directories
    DEFAULT_CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    DEFAULT_DATA_DIR.mkdir(parents=True, exist_ok=True)
    DEFAULT_LOG_DIR.mkdir(parents=True, exist_ok=True)
    
    # Create default config
    config = {
        "totp": {
            "issuer": "Airlock",
            "account": os.getlogin(),
            "digits": 6,
            "period": 30,
            "secret_path": str(DEFAULT_DATA_DIR / "totp_secret"),
        },
        "gateway": {
            "socket_path": str(DEFAULT_RUN_DIR / "gateway.sock"),
            "totp_socket_path": str(DEFAULT_RUN_DIR / "totp.sock"),
            "audit_log_path": str(DEFAULT_LOG_DIR / "audit.jsonl"),
        },
        "notifications": {
            "provider": "console",  # or "telegram"
            # telegram settings (if provider=telegram):
            # bot_token: ""
            # chat_id: ""
        },
        "credentials": {},
    }
    
    save_config(config)
    console.print(f"[green]Created config at {config_path}[/green]")
    console.print("\nNext steps:")
    console.print("  1. Run [bold]airlock totp setup[/bold] to configure TOTP")
    console.print("  2. Run [bold]airlock credentials add gmail[/bold] to add Gmail")
    console.print("  3. Run [bold]airlock start[/bold] to start the daemons")


@app.command("totp")
def totp_cmd(
    action: str = typer.Argument("setup", help="setup, show, or reset"),
):
    """Manage TOTP authentication."""
    config = load_config()
    totp_config = config.get("totp", {})
    
    secret_path = Path(totp_config.get("secret_path", DEFAULT_DATA_DIR / "totp_secret"))
    issuer = totp_config.get("issuer", "Airlock")
    account = totp_config.get("account", os.getlogin())
    digits = totp_config.get("digits", 6)
    period = totp_config.get("period", 30)
    
    if action == "setup":
        if secret_path.exists():
            if not typer.confirm("TOTP secret already exists. Reset it?"):
                raise typer.Abort()
        
        # Generate new secret
        secret = TOTPGenerator.generate_secret()
        totp = TOTPGenerator(secret, digits=digits, period=period)
        
        # Generate URI and QR code
        uri = totp.get_uri(issuer, account)
        
        console.print("\n[bold]TOTP Setup[/bold]\n")
        console.print("Scan this QR code with your authenticator app:\n")
        
        # Try to show QR code
        try:
            import qrcode
            qr = qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_L)
            qr.add_data(uri)
            qr.make(fit=True)
            qr.print_ascii(invert=True)
        except ImportError:
            console.print("[yellow]Install qrcode for QR display: pip install qrcode[/yellow]")
            console.print(f"\nManually enter this secret in your authenticator:")
            console.print(f"[bold]{totp.get_secret_base32()}[/bold]\n")
        
        # Verify pairing before saving
        console.print("\nEnter the 6-digit code from your authenticator to confirm pairing:\n")
        
        max_attempts = 3
        paired = False
        
        for attempt in range(max_attempts):
            code = typer.prompt("Code")
            
            if totp.verify(code):
                paired = True
                break
            else:
                remaining = max_attempts - attempt - 1
                if remaining > 0:
                    console.print(f"[red]Invalid code. {remaining} attempts remaining.[/red]")
                else:
                    console.print("[red]Too many failed attempts.[/red]")
        
        if not paired:
            console.print("\n[red]Pairing failed. Secret was not saved.[/red]")
            raise typer.Exit(1)
        
        # Save secret only after successful verification
        secret_path.parent.mkdir(parents=True, exist_ok=True)
        secret_path.write_text(totp.get_secret_base32())
        os.chmod(secret_path, 0o600)
        
        # Clear screen to remove QR code from terminal
        os.system('clear' if os.name != 'nt' else 'cls')
        
        console.print("[green]TOTP pairing successful![/green]")
        console.print(f"Secret saved to: {secret_path}")
        console.print("\nYour authenticator is now linked to Airlock.")
    
    elif action == "show":
        if not secret_path.exists():
            console.print("[red]No TOTP secret found. Run 'airlock totp setup' first.[/red]")
            raise typer.Exit(1)
        
        secret_b32 = secret_path.read_text().strip()
        totp = TOTPGenerator.from_base32(secret_b32, digits=digits, period=period)
        
        console.print(f"Current code: [bold]{totp.generate()}[/bold]")
    
    elif action == "reset":
        if secret_path.exists():
            if typer.confirm("This will invalidate your current authenticator. Continue?"):
                secret_path.unlink()
                console.print("[yellow]Secret deleted. Run 'airlock totp setup' to create new one.[/yellow]")
    
    else:
        console.print(f"[red]Unknown action: {action}[/red]")
        raise typer.Exit(1)


@app.command("credentials")
def credentials_cmd(
    action: str = typer.Argument(..., help="add, list, or remove"),
    service: str = typer.Argument(None, help="Service name (gmail, calendar)"),
    email: str = typer.Option(None, "--email", "-e", help="Email address"),
    password: str = typer.Option(None, "--password", "-p", help="App password"),
):
    """Manage service credentials."""
    config = load_config()
    credentials = config.get("credentials", {})
    
    if action == "list":
        table = Table(title="Configured Services")
        table.add_column("Service")
        table.add_column("Type")
        table.add_column("Account")
        table.add_column("Status")
        
        for svc, cred in credentials.items():
            table.add_row(
                svc,
                cred.get("type", "unknown"),
                cred.get("email", cred.get("account", "-")),
                "[green]configured[/green]",
            )
        
        if not credentials:
            table.add_row("-", "-", "-", "[dim]no services configured[/dim]")
        
        console.print(table)
    
    elif action == "add":
        if not service:
            console.print("[red]Service name required. Example: airlock credentials add gmail[/red]")
            raise typer.Exit(1)
        
        if service == "gmail":
            if not email or not password:
                console.print("[bold]Gmail Setup[/bold]\n")
                console.print("You'll need an App Password from Google.")
                console.print("Go to: https://myaccount.google.com/apppasswords\n")
            
            gmail_email = email or typer.prompt("Gmail address")
            app_password = password or typer.prompt("App password", hide_input=True)
            
            credentials["gmail"] = {
                "type": "imap",
                "email": gmail_email,
                "app_password": app_password,
                "imap_host": "imap.gmail.com",
                "imap_port": 993,
            }
            
            config["credentials"] = credentials
            save_config(config)
            
            console.print(f"\n[green]Gmail credentials saved for {gmail_email}[/green]")
        
        elif service == "calendar":
            console.print("[yellow]Google Calendar connector not yet implemented[/yellow]")
        
        else:
            console.print(f"[red]Unknown service: {service}[/red]")
            console.print("Supported services: gmail, calendar")
            raise typer.Exit(1)
    
    elif action == "remove":
        if not service:
            console.print("[red]Service name required[/red]")
            raise typer.Exit(1)
        
        if service in credentials:
            if typer.confirm(f"Remove credentials for {service}?"):
                del credentials[service]
                config["credentials"] = credentials
                save_config(config)
                console.print(f"[yellow]Removed {service} credentials[/yellow]")
        else:
            console.print(f"[red]No credentials found for {service}[/red]")
    
    else:
        console.print(f"[red]Unknown action: {action}[/red]")


@app.command()
def audit(
    service: str = typer.Option(None, help="Filter by service"),
    last: str = typer.Option("24h", help="Time range (e.g., 1h, 7d, today)"),
    limit: int = typer.Option(50, help="Maximum entries to show"),
):
    """View audit log."""
    config = load_config()
    audit_path = Path(config.get("gateway", {}).get("audit_log_path", DEFAULT_LOG_DIR / "audit.jsonl"))
    
    if not audit_path.exists():
        console.print("[dim]No audit log found yet.[/dim]")
        return
    
    console.print(f"[bold]Audit Log[/bold] (last {last})\n")
    
    table = Table()
    table.add_column("Time", style="dim")
    table.add_column("Event")
    table.add_column("Service")
    table.add_column("Operation")
    table.add_column("Result")
    
    entries = []
    with open(audit_path) as f:
        for line in f:
            try:
                entry = json.loads(line.strip())
                entries.append(entry)
            except json.JSONDecodeError:
                continue
    
    # Filter by service
    if service:
        entries = [e for e in entries if e.get("service") == service]
    
    # Show last N entries (newest last)
    entries = entries[-limit:]
    
    for entry in entries:
        ts = entry.get("ts", "")
        if ts:
            # Format timestamp
            try:
                dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                ts = dt.strftime("%H:%M:%S")
            except Exception:
                pass
        
        event = entry.get("event", "-")
        svc = entry.get("service", "-")
        op = entry.get("operation", "-")
        result = entry.get("result", entry.get("error", "-"))
        
        # Color result
        if result == "success":
            result = "[green]success[/green]"
        elif result and result != "-":
            result = f"[red]{result}[/red]"
        
        table.add_row(ts, event, svc, op, result)
    
    console.print(table)


@app.command()
def status():
    """Show Airlock service status."""
    config = load_config()
    
    console.print("[bold]Airlock Status[/bold]\n")
    
    # Check config
    config_path = get_config_path()
    if config_path.exists():
        console.print(f"  Config: [green]{config_path}[/green]")
    else:
        console.print(f"  Config: [red]not found[/red] (run 'airlock init')")
        return
    
    # Check TOTP secret
    secret_path = Path(config.get("totp", {}).get("secret_path", DEFAULT_DATA_DIR / "totp_secret"))
    if secret_path.exists():
        console.print(f"  TOTP:   [green]configured[/green]")
    else:
        console.print(f"  TOTP:   [yellow]not set up[/yellow] (run 'airlock totp setup')")
    
    # Check credentials
    credentials = config.get("credentials", {})
    if credentials:
        console.print(f"  Services: [green]{', '.join(credentials.keys())}[/green]")
    else:
        console.print(f"  Services: [yellow]none configured[/yellow]")
    
    console.print()
    
    # Check socket files (daemons running)
    gateway_socket = Path(config.get("gateway", {}).get("socket_path", DEFAULT_RUN_DIR / "gateway.sock"))
    totp_socket = Path(config.get("gateway", {}).get("totp_socket_path", DEFAULT_RUN_DIR / "totp.sock"))
    
    console.print("  Daemons:")
    if totp_socket.exists():
        console.print(f"    TOTP Verifier: [green]running[/green]")
    else:
        console.print(f"    TOTP Verifier: [red]stopped[/red]")
    
    if gateway_socket.exists():
        console.print(f"    Gateway:       [green]running[/green]")
    else:
        console.print(f"    Gateway:       [red]stopped[/red]")


@app.command()
def start(
    foreground: bool = typer.Option(False, "--foreground", "-f", help="Run in foreground (don't daemonize)"),
):
    """Start Airlock daemons."""
    config = load_config()
    
    # Check prerequisites
    secret_path = Path(config.get("totp", {}).get("secret_path", DEFAULT_DATA_DIR / "totp_secret"))
    if not secret_path.exists():
        console.print("[red]TOTP not configured. Run 'airlock totp setup' first.[/red]")
        raise typer.Exit(1)
    
    # Ensure run directory exists
    run_dir = DEFAULT_RUN_DIR
    run_dir.mkdir(parents=True, exist_ok=True)
    
    gateway_socket = Path(config.get("gateway", {}).get("socket_path", run_dir / "gateway.sock"))
    totp_socket = Path(config.get("gateway", {}).get("totp_socket_path", run_dir / "totp.sock"))
    
    # Check if already running
    if totp_socket.exists() or gateway_socket.exists():
        console.print("[yellow]Daemons may already be running. Run 'airlock stop' first.[/yellow]")
        if not typer.confirm("Continue anyway?"):
            raise typer.Abort()
    
    if foreground:
        console.print("[bold]Starting Airlock in foreground...[/bold]")
        console.print("Press Ctrl+C to stop.\n")
        
        import asyncio
        from airlock.totp_verifier import TOTPConfig, TOTPVerifier, ConsoleNotificationProvider
        from airlock.gateway import AccessGateway, GatewayConfig as GWConfig
        from airlock.connectors.gmail import GmailConnector, GmailConfig
        
        async def run_daemons():
            # Setup TOTP verifier
            totp_cfg = TOTPConfig(
                secret_path=secret_path,
                socket_path=totp_socket,
                issuer=config.get("totp", {}).get("issuer", "Airlock"),
            )
            verifier = TOTPVerifier(totp_cfg, ConsoleNotificationProvider())
            
            # Setup gateway
            gw_cfg = GWConfig(
                socket_path=gateway_socket,
                totp_socket_path=totp_socket,
                audit_log_path=Path(config.get("gateway", {}).get("audit_log_path", DEFAULT_LOG_DIR / "audit.jsonl")),
            )
            gateway = AccessGateway(gw_cfg)
            
            # Register connectors
            credentials = config.get("credentials", {})
            if "gmail" in credentials:
                gmail_cred = credentials["gmail"]
                gmail = GmailConnector(GmailConfig(
                    email=gmail_cred["email"],
                    app_password=gmail_cred["app_password"],
                ))
                gateway.register_connector(gmail)
                console.print(f"  Registered: gmail ({gmail_cred['email']})")
            
            console.print()
            
            # Run both daemons
            await asyncio.gather(
                verifier.start(),
                gateway.start(),
            )
        
        try:
            asyncio.run(run_daemons())
        except KeyboardInterrupt:
            console.print("\n[yellow]Shutting down...[/yellow]")
    else:
        # Background mode - spawn subprocess
        import subprocess
        
        # Get the path to this script
        script = sys.argv[0]
        
        proc = subprocess.Popen(
            [sys.executable, "-m", "airlock.cli", "start", "--foreground"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        
        console.print(f"[green]Airlock daemons starting (pid {proc.pid})...[/green]")
        console.print("Run 'airlock status' to check.")


@app.command()
def stop():
    """Stop Airlock daemons."""
    config = load_config()
    run_dir = DEFAULT_RUN_DIR
    
    gateway_socket = Path(config.get("gateway", {}).get("socket_path", run_dir / "gateway.sock"))
    totp_socket = Path(config.get("gateway", {}).get("totp_socket_path", run_dir / "totp.sock"))
    
    stopped = False
    
    # Remove socket files (daemons will detect and exit, or we're cleaning up stale sockets)
    if gateway_socket.exists():
        gateway_socket.unlink()
        console.print("  Removed gateway socket")
        stopped = True
    
    if totp_socket.exists():
        totp_socket.unlink()
        console.print("  Removed TOTP socket")
        stopped = True
    
    if stopped:
        console.print("[green]Airlock stopped.[/green]")
    else:
        console.print("[dim]No daemons were running.[/dim]")


@app.command()
def test():
    """Test TOTP verification (manual)."""
    config = load_config()
    totp_config = config.get("totp", {})
    
    secret_path = Path(totp_config.get("secret_path", DEFAULT_DATA_DIR / "totp_secret"))
    if not secret_path.exists():
        console.print("[red]TOTP not configured. Run 'airlock totp setup' first.[/red]")
        raise typer.Exit(1)
    
    secret_b32 = secret_path.read_text().strip()
    totp = TOTPGenerator.from_base32(
        secret_b32,
        digits=totp_config.get("digits", 6),
        period=totp_config.get("period", 30),
    )
    
    console.print("[bold]TOTP Verification Test[/bold]\n")
    console.print("Enter the code from your authenticator app:\n")
    
    code = typer.prompt("TOTP code")
    
    if totp.verify(code):
        console.print("\n[green]Verification successful![/green]")
    else:
        console.print("\n[red]Verification failed. Code incorrect or expired.[/red]")
        raise typer.Exit(1)


@app.command("run")
def run_cmd(
    service: str = typer.Argument(..., help="Service (gmail)"),
    operation: str = typer.Argument(..., help="Operation (list_messages, get_message, search, count_unread)"),
    params: str = typer.Option("{}", "--params", "-p", help="JSON params"),
    skip_totp: bool = typer.Option(False, "--skip-totp", help="Skip TOTP (for testing only)"),
):
    """Run a one-shot operation with TOTP approval."""
    import asyncio
    import json as json_lib
    
    config = load_config()
    credentials = config.get("credentials", {})
    
    if service not in credentials:
        console.print(f"[red]Service '{service}' not configured. Run 'airlock credentials add {service}'[/red]")
        raise typer.Exit(1)
    
    # Parse params
    try:
        op_params = json_lib.loads(params)
    except json_lib.JSONDecodeError:
        console.print("[red]Invalid JSON params[/red]")
        raise typer.Exit(1)
    
    # TOTP verification
    if not skip_totp:
        totp_config = config.get("totp", {})
        secret_path = Path(totp_config.get("secret_path", DEFAULT_DATA_DIR / "totp_secret"))
        
        if not secret_path.exists():
            console.print("[red]TOTP not configured.[/red]")
            raise typer.Exit(1)
        
        secret_b32 = secret_path.read_text().strip()
        totp = TOTPGenerator.from_base32(
            secret_b32,
            digits=totp_config.get("digits", 6),
            period=totp_config.get("period", 30),
        )
        
        console.print(f"\n[bold]Access Request[/bold]")
        console.print(f"  Service:   {service}")
        console.print(f"  Operation: {operation}")
        console.print(f"  Params:    {params}\n")
        
        code = typer.prompt("Enter TOTP code to approve")
        
        if not totp.verify(code):
            console.print("[red]Invalid TOTP code. Access denied.[/red]")
            raise typer.Exit(1)
        
        console.print("[green]Access granted.[/green]\n")
    
    # Execute operation
    if service == "gmail":
        from airlock.connectors.gmail import GmailConnector, GmailConfig
        
        cred = credentials["gmail"]
        connector = GmailConnector(GmailConfig(
            email=cred["email"],
            app_password=cred["app_password"],
        ))
        
        try:
            result = asyncio.run(connector.execute(operation, op_params))
            
            # Pretty print result
            if isinstance(result, list):
                console.print(f"[bold]Results ({len(result)} items):[/bold]\n")
                for item in result:
                    if isinstance(item, dict):
                        if "subject" in item:
                            # Email message
                            date = item.get("date", "")[:10] if item.get("date") else ""
                            from_info = item.get("from", {})
                            from_str = from_info.get("name") or from_info.get("email", "")
                            console.print(f"  [{date}] {from_str[:20]:<20} {item.get('subject', '')[:50]}")
                        else:
                            console.print(f"  {item}")
                    else:
                        console.print(f"  {item}")
            elif isinstance(result, dict):
                console.print(json_lib.dumps(result, indent=2, default=str))
            else:
                console.print(result)
        
        except Exception as e:
            console.print(f"[red]Error: {e}[/red]")
            raise typer.Exit(1)
    else:
        console.print(f"[red]Unknown service: {service}[/red]")
        raise typer.Exit(1)


@app.command()
def version():
    """Show version information."""
    from airlock import __version__
    console.print(f"Airlock v{__version__}")


if __name__ == "__main__":
    app()
