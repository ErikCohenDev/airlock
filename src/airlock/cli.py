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
        
        # Save secret
        secret_path.parent.mkdir(parents=True, exist_ok=True)
        secret_path.write_text(totp.get_secret_base32())
        os.chmod(secret_path, 0o600)
        
        # Generate URI and QR code
        uri = totp.get_uri(issuer, account)
        
        console.print("\n[bold]TOTP Setup Complete[/bold]\n")
        console.print(f"Secret saved to: {secret_path}")
        console.print(f"\nSetup URI:\n[dim]{uri}[/dim]\n")
        
        # Try to show QR code
        try:
            import qrcode
            qr = qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_L)
            qr.add_data(uri)
            qr.make(fit=True)
            
            console.print("Scan this QR code with your authenticator app:\n")
            qr.print_ascii(invert=True)
        except ImportError:
            console.print("[yellow]Install qrcode for QR display: pip install qrcode[/yellow]")
            console.print(f"\nManually enter this secret in your authenticator:")
            console.print(f"[bold]{totp.get_secret_base32()}[/bold]")
        
        # Show current code for verification
        console.print(f"\nCurrent code: [bold]{totp.generate()}[/bold]")
        console.print("(Verify this matches your authenticator app)")
    
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
            console.print("[bold]Gmail Setup[/bold]\n")
            console.print("You'll need an App Password from Google.")
            console.print("Go to: https://myaccount.google.com/apppasswords\n")
            
            email = typer.prompt("Gmail address")
            app_password = typer.prompt("App password", hide_input=True)
            
            credentials["gmail"] = {
                "type": "imap",
                "email": email,
                "app_password": app_password,
                "imap_host": "imap.gmail.com",
                "imap_port": 993,
            }
            
            config["credentials"] = credentials
            save_config(config)
            
            console.print(f"\n[green]Gmail credentials saved for {email}[/green]")
        
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


@app.command()
def version():
    """Show version information."""
    from airlock import __version__
    console.print(f"Airlock v{__version__}")


if __name__ == "__main__":
    app()
