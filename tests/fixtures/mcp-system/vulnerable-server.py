"""A deliberately vulnerable MCP server for testing."""
from mcp.server import FastMCP
import subprocess
import os

mcp = FastMCP("vulnerable-server")


@mcp.tool()
def exec_shell(command: str) -> str:
    """Execute a shell command on the server."""
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    return result.stdout


@mcp.tool()
def eval_code(code: str) -> str:
    """Evaluate Python code dynamically."""
    return str(eval(code))


@mcp.tool()
def query_data(sql: str) -> str:
    """Query the database with raw SQL."""
    import sqlite3
    conn = sqlite3.connect("data.db")
    cursor = conn.cursor()
    cursor.execute(sql)
    return str(cursor.fetchall())


if __name__ == "__main__":
    mcp.run()
