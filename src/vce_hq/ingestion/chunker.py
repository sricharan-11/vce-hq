"""Text chunker for knowledge documents.

Splits documents into overlapping chunks suitable for embedding.
The chunking strategy uses a recursive character-based approach:
    1. Split on paragraph boundaries (double newlines)
    2. If chunks are still too large, split on sentence boundaries
    3. If still too large, split on word boundaries

Overlap ensures that context is preserved across chunk boundaries,
which is critical for retrieval quality.
"""


class TextChunker:
    """Splits text into overlapping chunks for embedding.

    Args:
        chunk_size: Target maximum characters per chunk.
        chunk_overlap: Number of overlapping characters between consecutive chunks.
    """

    def __init__(
        self,
        chunk_size: int = 1000,
        chunk_overlap: int = 200,
    ) -> None:
        if chunk_overlap >= chunk_size:
            raise ValueError("chunk_overlap must be less than chunk_size")
        self._chunk_size = chunk_size
        self._chunk_overlap = chunk_overlap

    def chunk(self, text: str) -> list[str]:
        """Split text into chunks with overlap.

        Args:
            text: The full document text to split.

        Returns:
            A list of text chunks. Empty input returns an empty list.
        """
        if not text or not text.strip():
            return []

        # Normalize whitespace
        text = text.strip()

        # If the text fits in a single chunk, return it directly.
        if len(text) <= self._chunk_size:
            return [text]

        # Step 1: Split on paragraph boundaries
        paragraphs = self._split_on_separators(text, ["\n\n", "\n"])

        # Step 2: Merge paragraphs into chunks respecting size limits
        return self._merge_into_chunks(paragraphs)

    def _split_on_separators(self, text: str, separators: list[str]) -> list[str]:
        """Recursively split text using a hierarchy of separators.

        Args:
            text: Text to split.
            separators: Ordered list of separators to try.

        Returns:
            List of text segments.
        """
        if not separators:
            # Base case: split on spaces (word-level)
            return text.split(" ")

        separator = separators[0]
        remaining_separators = separators[1:]

        parts = text.split(separator)
        result: list[str] = []

        for part in parts:
            part = part.strip()
            if not part:
                continue
            if len(part) <= self._chunk_size:
                result.append(part)
            else:
                # Recursively split oversized segments
                result.extend(
                    self._split_on_separators(part, remaining_separators)
                )

        return result

    def _merge_into_chunks(self, segments: list[str]) -> list[str]:
        """Merge small segments into chunks with overlap.

        Args:
            segments: Pre-split text segments.

        Returns:
            List of merged chunks.
        """
        chunks: list[str] = []
        current_chunk: list[str] = []
        current_length = 0

        for segment in segments:
            segment_length = len(segment)

            # Would adding this segment exceed the chunk size?
            if current_length + segment_length + 1 > self._chunk_size and current_chunk:
                # Finalize the current chunk
                chunks.append(" ".join(current_chunk))

                # Keep overlap: retain segments from the tail of the current chunk
                overlap_segments: list[str] = []
                overlap_length = 0
                for prev_segment in reversed(current_chunk):
                    if overlap_length + len(prev_segment) + 1 > self._chunk_overlap:
                        break
                    overlap_segments.insert(0, prev_segment)
                    overlap_length += len(prev_segment) + 1

                current_chunk = overlap_segments
                current_length = overlap_length

            current_chunk.append(segment)
            current_length += segment_length + 1

        # Don't forget the last chunk
        if current_chunk:
            chunks.append(" ".join(current_chunk))

        return chunks
