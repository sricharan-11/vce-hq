"""Agnostic Embedding Service.

Provides a thin, typed wrapper around Langchain embedding models.
Supports both single-text and batch embedding.

Usage:
    from vce_hq.embeddings.service import EmbeddingService

    svc = EmbeddingService()
    vector = await svc.embed("What is a kernel panic?")
    vectors = await svc.embed_batch(["doc chunk 1", "doc chunk 2"])
"""

import asyncio
import logging
from typing import Sequence

from vce_hq.config import settings

logger = logging.getLogger(__name__)

class EmbeddingService:
    """Async client for embedding generation using the configured provider.

    Configured from ``vce_hq.config.settings`` at initialization.
    """

    def __init__(self) -> None:
        self._provider = settings.embedding_provider.lower()
        self._model = settings.embedding_model
        self._dimensions = settings.embedding_dimensions
        
        # Instantiate the correct Langchain embeddings class
        if self._provider == "openai":
            from langchain_openai import OpenAIEmbeddings
            kwargs = {"model": self._model}
            if settings.openai_api_key:
                kwargs["api_key"] = settings.openai_api_key
            if settings.openai_api_base:
                kwargs["base_url"] = settings.openai_api_base
            if self._dimensions:
                kwargs["dimensions"] = self._dimensions
            self._client = OpenAIEmbeddings(**kwargs)
            
        elif self._provider in ["google_genai", "google"]:
            from langchain_google_genai import GoogleGenerativeAIEmbeddings
            kwargs = {"model": f"models/{self._model}"}
            if settings.google_api_key:
                kwargs["google_api_key"] = settings.google_api_key
            self._client = GoogleGenerativeAIEmbeddings(**kwargs)
            
        else:
            raise ValueError(f"Unsupported embedding provider: {self._provider}")

    async def embed(self, text: str, *, task_type: str = "RETRIEVAL_DOCUMENT") -> list[float]:
        """Embed a single text string."""
        if task_type == "RETRIEVAL_QUERY":
            result = await self._client.aembed_query(text)
        else:
            results = await self._client.aembed_documents([text])
            result = results[0]
        
        if self._dimensions and len(result) > self._dimensions:
            return result[:self._dimensions]
        return result

    async def embed_query(self, text: str) -> list[float]:
        """Embed a search query."""
        return await self.embed(text, task_type="RETRIEVAL_QUERY")

    async def embed_batch(
        self,
        texts: Sequence[str],
        *,
        task_type: str = "RETRIEVAL_DOCUMENT",
        batch_size: int = 100,
    ) -> list[list[float]]:
        """Embed a batch of texts."""
        text_list = list(texts)
        if not text_list:
            return []
            
        # Langchain handles chunking and rate limits internally for most providers
        results = await self._client.aembed_documents(text_list)
        if self._dimensions:
            return [res[:self._dimensions] if len(res) > self._dimensions else res for res in results]
        return results

    # Alias used by inventory capture for clarity
    embed_async = embed
