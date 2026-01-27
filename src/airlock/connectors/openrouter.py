"""OpenRouter Connector — API access to cloud LLMs and embeddings.

Provides:
- embed: Generate embeddings via OpenRouter-compatible models
- complete: Generate text completions
- list_models: List available models

Supported models for embeddings:
- openai/text-embedding-3-small
- openai/text-embedding-3-large
- voyage/voyage-3-lite

API key is stored encrypted via Airlock secrets:
    airlock secrets set openrouter api_key -v "sk-or-..."
"""

from dataclasses import dataclass, field
from typing import Any, Optional

import httpx


OPENROUTER_BASE_URL = "https://openrouter.ai/api/v1"


@dataclass
class OpenRouterConfig:
    """OpenRouter API configuration.
    
    If api_key is not provided, will attempt to load from Airlock encrypted secrets.
    """
    api_key: Optional[str] = None  # If None, loads from encrypted secrets
    base_url: str = OPENROUTER_BASE_URL
    default_embed_model: str = "openai/text-embedding-3-small"
    timeout: float = 60.0
    
    def __post_init__(self):
        if self.api_key is None:
            self.api_key = self._load_from_secrets()
    
    def _load_from_secrets(self) -> str:
        """Load API key from Airlock encrypted secrets."""
        try:
            from airlock.secrets import get_secret
            api_key = get_secret("openrouter", "api_key")
            if api_key:
                return api_key
        except Exception:
            pass
        
        # Fallback to environment variable
        import os
        api_key = os.environ.get("OPENROUTER_API_KEY")
        if api_key:
            return api_key
        
        raise ValueError(
            "OpenRouter API key not found. Either:\n"
            "  1. Run: airlock secrets set openrouter api_key\n"
            "  2. Set OPENROUTER_API_KEY environment variable"
        )


class OpenRouterConnector:
    """OpenRouter API connector for embeddings and completions."""
    
    def __init__(self, config: OpenRouterConfig):
        self.config = config
        self._client = None
    
    @property
    def service_name(self) -> str:
        return "openrouter"
    
    def _get_client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(
                timeout=self.config.timeout,
                headers={
                    "Authorization": f"Bearer {self.config.api_key}",
                    "Content-Type": "application/json",
                    "HTTP-Referer": "https://github.com/clawdbot",  # Optional, for rankings
                }
            )
        return self._client
    
    async def close(self):
        if self._client:
            await self._client.aclose()
            self._client = None
    
    async def execute(self, action: str, params: dict[str, Any] = None) -> Any:
        """Execute an action."""
        params = params or {}
        
        actions = {
            "embed": self._embed,
            "complete": self._complete,
            "list_models": self._list_models,
        }
        
        if action not in actions:
            raise ValueError(f"Unknown action: {action}. Available: {list(actions.keys())}")
        
        return await actions[action](**params)
    
    async def _embed(
        self,
        text: str | list[str],
        model: str = None,
    ) -> list[float] | list[list[float]]:
        """Generate embeddings for text.
        
        Args:
            text: Single string or list of strings to embed
            model: Model to use (default: config.default_embed_model)
        
        Returns:
            Embedding vector(s)
        """
        model = model or self.config.default_embed_model
        client = self._get_client()
        
        # Normalize to list
        texts = [text] if isinstance(text, str) else text
        single_input = isinstance(text, str)
        
        response = await client.post(
            f"{self.config.base_url}/embeddings",
            json={
                "model": model,
                "input": texts,
            }
        )
        response.raise_for_status()
        data = response.json()
        
        embeddings = [item["embedding"] for item in data["data"]]
        
        return embeddings[0] if single_input else embeddings
    
    async def _complete(
        self,
        prompt: str,
        model: str = "openai/gpt-4o-mini",
        max_tokens: int = 500,
        temperature: float = 0.7,
    ) -> str:
        """Generate text completion.
        
        Args:
            prompt: Input prompt
            model: Model to use
            max_tokens: Maximum tokens to generate
            temperature: Sampling temperature
        
        Returns:
            Generated text
        """
        client = self._get_client()
        
        response = await client.post(
            f"{self.config.base_url}/chat/completions",
            json={
                "model": model,
                "messages": [{"role": "user", "content": prompt}],
                "max_tokens": max_tokens,
                "temperature": temperature,
            }
        )
        response.raise_for_status()
        data = response.json()
        
        return data["choices"][0]["message"]["content"]
    
    async def _list_models(self, filter_type: str = None) -> list[dict]:
        """List available models.
        
        Args:
            filter_type: Filter by type (e.g., "embedding", "chat")
        
        Returns:
            List of model info dicts
        """
        client = self._get_client()
        
        response = await client.get(f"{self.config.base_url}/models")
        response.raise_for_status()
        data = response.json()
        
        models = data.get("data", [])
        
        if filter_type:
            # Simple filter by model ID patterns
            if filter_type == "embedding":
                models = [m for m in models if "embed" in m.get("id", "").lower()]
        
        return models


# Convenience function for direct use
async def get_embedding(
    text: str,
    api_key: str = None,
    model: str = "openai/text-embedding-3-small",
) -> list[float]:
    """Quick embedding without full connector setup.
    
    Args:
        text: Text to embed
        api_key: OpenRouter API key (or reads from OPENROUTER_API_KEY env)
        model: Embedding model
    
    Returns:
        Embedding vector
    """
    import os
    
    api_key = api_key or os.environ.get("OPENROUTER_API_KEY")
    if not api_key:
        raise ValueError("No API key provided. Set OPENROUTER_API_KEY or pass api_key.")
    
    config = OpenRouterConfig(api_key=api_key)
    connector = OpenRouterConnector(config)
    
    try:
        return await connector.execute("embed", {"text": text, "model": model})
    finally:
        await connector.close()
