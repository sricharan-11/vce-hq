"""Manager for Gemini Context Caching.

This ensures we only create expensive context caches when necessary,
and reuse them across agent invocations to drastically reduce prompt token usage.
"""
import logging
import hashlib
import time
from typing import Optional, Any

from langchain_core.messages import SystemMessage
from langchain_google_genai import create_context_cache
from vce_hq.llm_factory import get_llm
from vce_hq.config import settings

logger = logging.getLogger(__name__)

class CacheManager:
    """Manages Gemini context caches."""
    
    def __init__(self):
        # Maps cache_key -> (cache_name, expiry_timestamp)
        self._active_caches: dict[str, tuple[str, float]] = {}
        
    def _compute_cache_key(self, model: str, system_prompt: str, env_context: str, tools: list[Any] = None) -> str:
        """Compute a deterministic hash for the cache contents."""
        content = f"{model}|{system_prompt}|{env_context}"
        if tools:
            # Simple hash of tool names to detect changes
            tool_names = [getattr(t, "name", str(t)) for t in tools]
            content += "|" + ",".join(tool_names)
        return hashlib.sha256(content.encode()).hexdigest()

    def get_or_create_cache(
        self,
        model_name: str,
        system_prompt: str,
        env_context: str,
        tools: list[Any] = None,
        ttl: str = "3600s",
    ) -> Optional[str]:
        """Get an existing cache or create a new one.
        
        Args:
            model_name: The Gemini model name.
            system_prompt: The agent's base instructions.
            env_context: The stringified EnvironmentProfile.
            tools: The tools to bind to the LLM.
            ttl: How long the cache should live.
            
        Returns:
            The cache_name string if successful, or None if the payload was too small
            or an error occurred (falling back to stateless).
        """
        if settings.llm_provider.lower() not in ["google_genai", "google"]:
            # OpenAI, Anthropic, DeepSeek handle caching natively behind the scenes
            return None
            
        cache_key = self._compute_cache_key(model_name, system_prompt, env_context, tools)
        
        if cache_key in self._active_caches:
            cache_name, expiry = self._active_caches[cache_key]
            if time.time() < expiry:
                return cache_name
            else:
                logger.info("Context Cache expired, creating new one for key: %s", cache_key[:8])
                del self._active_caches[cache_key]
            
        try:
            logger.info("Attempting to create Gemini Context Cache for key: %s", cache_key[:8])
            
            messages = [SystemMessage(content=system_prompt)]
            if env_context:
                messages.append(SystemMessage(content=env_context))
                
            temp_model = get_llm()
            
            cache_name = create_context_cache(
                model=temp_model,
                messages=messages,
                tools=tools,
                ttl=ttl
            )
            
            # Parse ttl string e.g. "3600s" to int. Default to 3600 if parsing fails.
            try:
                ttl_seconds = int(ttl.strip('s'))
            except ValueError:
                ttl_seconds = 3600
                
            # Keep a 5-minute (300s) buffer before actual expiration
            expiry_timestamp = time.time() + ttl_seconds - 300
            
            logger.info("Successfully created context cache: %s", cache_name)
            self._active_caches[cache_key] = (cache_name, expiry_timestamp)
            return cache_name
            
        except Exception as e:
            # This often happens if the context is smaller than the 32k token minimum
            logger.warning("Failed to create context cache (falling back to stateless): %s", e)
            return None

# Global singleton
cache_manager = CacheManager()
