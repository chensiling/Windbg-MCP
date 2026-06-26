import os
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class Config:
    http_port: int = 8080
    connect_host: str = "127.0.0.1"
    connect_port: int = 50000
    command_timeout: int = 30
    max_retries: int = 3
    debug_json: bool = False
    auth_token: Optional[str] = None

    @classmethod
    def from_env(cls) -> "Config":
        return cls(
            http_port=int(os.getenv("WINDBG_MCP_HTTP_PORT", "8080")),
            connect_host=os.getenv("WINDBG_MCP_DEBUG_HOST", "127.0.0.1"),
            connect_port=int(os.getenv("WINDBG_MCP_DEBUG_PORT", "50000")),
            command_timeout=int(os.getenv("WINDBG_MCP_TIMEOUT", "30")),
            max_retries=int(os.getenv("WINDBG_MCP_RETRIES", "3")),
            debug_json=os.getenv("WINDBG_MCP_DEBUG_JSON", "").lower() in ("1", "true", "yes"),
            auth_token=os.getenv("WINDBG_MCP_TOKEN", None),
        )

    def apply_cli(self, **kwargs) -> "Config":
        for key, value in kwargs.items():
            if value is not None and hasattr(self, key):
                setattr(self, key, value)
        return self
