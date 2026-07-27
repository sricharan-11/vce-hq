"""Factory for creating LLM instances dynamically."""

import logging
from typing import Any

from langchain.chat_models import init_chat_model
from langchain_core.language_models.chat_models import BaseChatModel

from vce_hq.config import settings

logger = logging.getLogger(__name__)


def get_llm(provider: str | None = None, model_name: str | None = None, **kwargs: Any) -> BaseChatModel:
    """Instantiate a chat model based on the configured provider.
    
    Args:
        provider: Optional override for the LLM provider.
        model_name: Optional override for the LLM model name.
        **kwargs: Additional arguments to pass to the model (e.g. temperature).
        
    Returns:
        A Langchain BaseChatModel instance.
    """
    provider = (provider or settings.llm_provider).lower()
    model_name = model_name or settings.llm_model

    # Mapping custom provider names to Langchain supported provider strings
    langchain_provider = provider
    
    # Optional arguments to inject based on provider
    provider_kwargs = {}
    
    if provider == "openai":
        if settings.openai_api_key:
            provider_kwargs["api_key"] = settings.openai_api_key
        if settings.openai_api_base:
            provider_kwargs["base_url"] = settings.openai_api_base
            
    elif provider == "anthropic":
        if settings.anthropic_api_key:
            provider_kwargs["api_key"] = settings.anthropic_api_key
            
    elif provider == "google_genai" or provider == "google":
        langchain_provider = "google_genai"
        if settings.google_api_key:
            provider_kwargs["api_key"] = settings.google_api_key
            
    elif provider == "deepseek":
        langchain_provider = "openai"
        provider_kwargs["base_url"] = "https://api.deepseek.com/v1"
        if settings.deepseek_api_key:
            provider_kwargs["api_key"] = settings.deepseek_api_key
            
    elif provider == "qwen":
        langchain_provider = "openai"
        provider_kwargs["base_url"] = "https://dashscope-intl.aliyuncs.com/compatible-mode/v1"
        if settings.qwen_api_key:
            provider_kwargs["api_key"] = settings.qwen_api_key

    # Merge provider kwargs with user-supplied kwargs
    # User-supplied kwargs (like temperature) take precedence
    final_kwargs = {**provider_kwargs, **kwargs}
    final_kwargs.pop("model", None)
    final_kwargs.pop("model_provider", None)
    
    logger.debug("Initializing LLM: %s via %s", model_name, langchain_provider)

    return init_chat_model(
        model=model_name,
        model_provider=langchain_provider,
        **final_kwargs
    )
