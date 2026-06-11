"""Tests for the text chunker."""

import pytest

from vce_hq.ingestion.chunker import TextChunker


class TestTextChunker:
    """Tests for document chunking logic."""

    def test_empty_text(self) -> None:
        chunker = TextChunker(chunk_size=100, chunk_overlap=20)
        assert chunker.chunk("") == []
        assert chunker.chunk("   ") == []

    def test_small_text_single_chunk(self) -> None:
        chunker = TextChunker(chunk_size=100, chunk_overlap=20)
        result = chunker.chunk("Hello world")
        assert len(result) == 1
        assert result[0] == "Hello world"

    def test_large_text_multiple_chunks(self) -> None:
        chunker = TextChunker(chunk_size=50, chunk_overlap=10)
        text = "A" * 30 + "\n\n" + "B" * 30 + "\n\n" + "C" * 30
        result = chunker.chunk(text)
        assert len(result) >= 2

    def test_overlap_preserved(self) -> None:
        chunker = TextChunker(chunk_size=50, chunk_overlap=10)
        text = "word1 word2 word3 word4 word5 word6 word7 word8 word9 word10 word11 word12 word13 word14 word15"
        result = chunker.chunk(text)
        if len(result) >= 2:
            # Check that some content from the end of chunk 1
            # appears at the start of chunk 2
            chunk1_words = set(result[0].split())
            chunk2_words = set(result[1].split())
            overlap = chunk1_words & chunk2_words
            assert len(overlap) > 0, "Expected overlap between consecutive chunks"

    def test_invalid_overlap_raises(self) -> None:
        with pytest.raises(ValueError, match="chunk_overlap must be less than chunk_size"):
            TextChunker(chunk_size=100, chunk_overlap=100)

    def test_paragraph_splitting(self) -> None:
        chunker = TextChunker(chunk_size=100, chunk_overlap=20)
        text = "Paragraph one content.\n\nParagraph two content.\n\nParagraph three content."
        result = chunker.chunk(text)
        # Small enough to fit in one chunk
        assert len(result) >= 1


class TestWebhookNormalizer:
    """Tests for webhook event normalization."""

    def test_datadog_normalization(self) -> None:
        from vce_hq.webhooks.normalizer import normalize_datadog
        from vce_hq.webhooks.schemas import DatadogWebhookPayload

        payload = DatadogWebhookPayload(
            title="High CPU Alert",
            body="CPU usage is 98%",
            alert_type="error",
            tags="env:prod, service:api",
        )
        event = normalize_datadog("tenant-1", payload)
        assert event.source == "datadog"
        assert event.severity == "critical"
        assert event.title == "High CPU Alert"
        assert "env:prod" in event.tags

    def test_custom_normalization(self) -> None:
        from vce_hq.webhooks.normalizer import normalize_custom
        from vce_hq.webhooks.schemas import CustomWebhookPayload

        payload = CustomWebhookPayload(
            title="Disk Full",
            body="/var is at 95%",
            severity="critical",
            tags=["disk", "production"],
        )
        event = normalize_custom("tenant-1", payload)
        assert event.source == "custom"
        assert event.severity == "critical"
        assert "disk" in event.tags
