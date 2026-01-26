"""Airlock CLI — Command-line interface for setup and management."""

import typer
from rich.console import Console
from rich.table import Table

app = typer.Typer(
    name="airlock",
    help="Secure Access Gateway — Human-in-the-loop access control for AI agents",
)
console = Console()


@app.command()
def setup():
    """Initial setup wizard."""
    console.print("[bold]Airlock Setup[/bold]\n")
    console.print("This will:")
    console.print("  1. Create system users (airlock-totp, airlock-gateway)")
    console.print("  2. Generate TOTP secret and show QR code")
    console.print("  3. Set up directory structure")
    console.print("  4. Install systemd services")
    console.print()
    
    if not typer.confirm("Continue?"):
        raise typer.Abort()
    
    # TODO: Implement setup
    console.print("[yellow]Setup not yet implemented[/yellow]")


@app.command()
def totp():
    """Set up or reset TOTP authentication."""
    console.print("[bold]TOTP Setup[/bold]\n")
    console.print("This will generate a new TOTP secret.")
    console.print("Scan the QR code with your authenticator app.")
    console.print()
    
    # TODO: Generate TOTP secret, display QR code
    console.print("[yellow]TOTP setup not yet implemented[/yellow]")


@app.command()
def credentials(action: str = typer.Argument(..., help="add, list, or remove")):
    """Manage service credentials."""
    if action == "add":
        console.print("[yellow]Add credentials not yet implemented[/yellow]")
    elif action == "list":
        table = Table(title="Configured Services")
        table.add_column("Service")
        table.add_column("Type")
        table.add_column("Status")
        # TODO: List actual credentials
        console.print(table)
    elif action == "remove":
        console.print("[yellow]Remove credentials not yet implemented[/yellow]")
    else:
        console.print(f"[red]Unknown action: {action}[/red]")


@app.command()
def audit(
    service: str = typer.Option(None, help="Filter by service"),
    last: str = typer.Option("24h", help="Time range (e.g., 1h, 7d)"),
):
    """View audit log."""
    console.print(f"[bold]Audit Log[/bold] (last {last})\n")
    
    table = Table()
    table.add_column("Time")
    table.add_column("Event")
    table.add_column("Service")
    table.add_column("Operation")
    table.add_column("Result")
    
    # TODO: Load actual audit entries
    console.print(table)
    console.print("[yellow]Audit log not yet implemented[/yellow]")


@app.command()
def tokens(action: str = typer.Argument("list", help="list, revoke")):
    """Manage active tokens."""
    if action == "list":
        table = Table(title="Active Tokens")
        table.add_column("Token ID")
        table.add_column("Services")
        table.add_column("Issued")
        table.add_column("Expires")
        table.add_column("Status")
        # TODO: List actual tokens
        console.print(table)
    elif action == "revoke":
        token_id = typer.prompt("Token ID to revoke")
        console.print(f"[yellow]Revoking {token_id}... not yet implemented[/yellow]")


@app.command()
def status():
    """Show Airlock service status."""
    console.print("[bold]Airlock Status[/bold]\n")
    
    # TODO: Check actual service status
    services = [
        ("airlock-totp", "unknown"),
        ("airlock-gateway", "unknown"),
    ]
    
    for name, svc_status in services:
        if svc_status == "running":
            console.print(f"  {name}: [green]{svc_status}[/green]")
        else:
            console.print(f"  {name}: [red]{svc_status}[/red]")


if __name__ == "__main__":
    app()
