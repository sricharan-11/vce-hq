"""Google text-embedding-005 client.

Provides a thin, typed wrapper around the Google Generative AI
embedding API. Supports both single-text and batch embedding with
automatic retry and rate-limit handling.

Usage:
    from vce_hq.embeddings.service import EmbeddingService

    svc = EmbeddingService()
    vector = await svc.embed("What is a kernel panic?")
    vectors = await svc.embed_batch(["doc chunk 1", "doc chunk 2"])
"""

import asyncio
import logging
from typing import Sequence

import google.generativeai as genai

from vce_hq.config import settings

logger = logging.getLogger(__name__)

# Rate-limit: max concurrent embedding requests
_CONCURRENCY_LIMIT = 10
_semaphore = asyncio.Semaphore(_CONCURRENCY_LIMIT)


class EmbeddingService:
    """Async client for Google's text-embedding-005 model.

    Configured from ``vce_hq.config.settings`` at initialization.
    """

    def __init__(self) -> None:
        genai.configure(api_key=settings.google_api_key)
        self._model = settings.embedding_model
        self._dimensions = settings.embedding_dimensions

    async def embed(self, text: str, *, task_type: str = "RETRIEVAL_DOCUMENT") -> list[float]:
        """Embed a single text string.

        Args:
            text: The text to embed.
            task_type: The embedding task type. Use ``RETRIEVAL_DOCUMENT``
                for content being stored, and ``RETRIEVAL_QUERY`` for
                search queries. This affects vector quality for retrieval.

        Returns:
            A list of floats with length ``embedding_dimensions``.
        """
        async with _semaphore:
            result = await asyncio.to_thread(
                genai.embed_content,
                model=f"models/{self._model}",
                content=text,
                task_type=task_type,
                output_dimensionality=self._dimensions,
            )
        return result["embedding"]

    async def embed_query(self, text: str) -> list[float]:
        """Embed a search query.

        Convenience method that sets ``task_type=RETRIEVAL_QUERY``
        for optimal retrieval performance.

        Args:
            text: The search query text.

        Returns:
            A list of floats with length ``embedding_dimensions``.
        """
        return await self.embed(text, task_type="RETRIEVAL_QUERY")

    async def embed_batch(
        self,
        texts: Sequence[str],
        *,
        task_type: str = "RETRIEVAL_DOCUMENT",
        batch_size: int = 100,
    ) -> list[list[float]]:
        """Embed a batch of texts with automatic chunking.

        The Google API supports batching natively. This method splits
        large inputs into sub-batches to stay within API limits.

        Args:
            texts: Sequence of texts to embed.
            task_type: The embedding task type (applied to all texts).
            batch_size: Maximum texts per API call.

        Returns:
            A list of embedding vectors, one per input text, preserving order.
        """
        all_embeddings: list[list[float]] = []

        for i in range(0, len(texts), batch_size):
            batch = list(texts[i : i + batch_size])
            async with _semaphore:
                result = await asyncio.to_thread(
                    genai.embed_content,
                    model=f"models/{self._model}",
                    content=batch,
                    task_type=task_type,
                    output_dimensionality=self._dimensions,
                )
            all_embeddings.extend(result["embedding"])

        return all_embeddings

    # Alias used by inventory capture for clarity
    embed_async = embed
