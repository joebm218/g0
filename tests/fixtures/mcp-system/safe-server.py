"""A well-designed MCP server for testing."""
from mcp.server import FastMCP
from pydantic import BaseModel, validator

mcp = FastMCP("safe-server")


class FileReadRequest(BaseModel):
    path: str

    @validator("path")
    def validate_path(cls, v):
        if ".." in v or v.startswith("/"):
            raise ValueError("Invalid path")
        return v


@mcp.tool()
def read_file(request: FileReadRequest) -> str:
    """Read a file from the allowed directory."""
    with open(f"./data/{request.path}") as f:
        return f.read()


@mcp.tool()
def get_status() -> str:
    """Get the server status."""
    return "OK"


if __name__ == "__main__":
    mcp.run()
