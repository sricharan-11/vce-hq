"""Event normalizer: transforms source-specific payloads into NormalizedEvent.

Each webhook source has its own quirks:
    - Datadog sends tags as a comma-separated string
    - CloudWatch wraps the alarm in an SNS envelope
    - Custom payloads are pass-through with defaults

The normalizer handles these differences so the rest of the pipeline
only ever sees ``NormalizedEvent``.
"""

import json
import logging
from typing import Any

from vce_hq.db.models import EventSeverity, EventSource, NormalizedEvent
from vce_hq.webhooks.schemas import (
    CloudWatchWebhookPayload,
    CustomWebhookPayload,
    DatadogWebhookPayload,
)

logger = logging.getLogger(__name__)


def normalize_datadog(
    tenant_id: str, payload: DatadogWebhookPayload
) -> NormalizedEvent:
    """Normalize a Datadog webhook payload.

    Args:
        tenant_id: The tenant receiving this alert.
        payload: The parsed Datadog webhook body.

    Returns:
        A normalized event.
    """
    severity = _map_datadog_severity(payload.alert_type)
    tags = [t.strip() for t in payload.tags.split(",") if t.strip()]

    return NormalizedEvent(
        tenant_id=tenant_id,
        source=EventSource.DATADOG,
        severity=severity,
        title=payload.title or "Datadog Alert",
        body=payload.body or "",
        tags=tags,
        raw_payload=payload.raw or payload.model_dump(),
    )


def normalize_cloudwatch(
    tenant_id: str, payload: CloudWatchWebhookPayload
) -> NormalizedEvent:
    """Normalize a CloudWatch/SNS webhook payload.

    The actual alarm details are inside the ``Message`` field as a
    JSON string. We parse that and extract structured data.

    Args:
        tenant_id: The tenant receiving this alert.
        payload: The parsed SNS notification body.

    Returns:
        A normalized event.
    """
    # Parse the inner alarm message
    alarm: dict[str, Any] = {}
    try:
        alarm = json.loads(payload.Message) if payload.Message else {}
    except json.JSONDecodeError:
        logger.warning("Failed to parse CloudWatch alarm message as JSON")
        alarm = {"raw_message": payload.Message}

    severity = _map_cloudwatch_severity(alarm.get("NewStateValue", ""))
    title = payload.Subject or alarm.get("AlarmName", "CloudWatch Alert")
    body = alarm.get("NewStateReason", payload.Message or "")

    tags: list[str] = []
    if alarm.get("AlarmName"):
        tags.append(f"alarm:{alarm['AlarmName']}")
    if alarm.get("Namespace"):
        tags.append(f"namespace:{alarm['Namespace']}")
    if alarm.get("MetricName"):
        tags.append(f"metric:{alarm['MetricName']}")

    return NormalizedEvent(
        tenant_id=tenant_id,
        source=EventSource.CLOUDWATCH,
        severity=severity,
        title=title,
        body=body,
        tags=tags,
        raw_payload=payload.raw or payload.model_dump(),
    )


def normalize_custom(
    tenant_id: str, payload: CustomWebhookPayload
) -> NormalizedEvent:
    """Normalize a custom/generic webhook payload.

    This is the most straightforward normalizer — the custom schema
    already closely matches NormalizedEvent.

    Args:
        tenant_id: The tenant receiving this alert.
        payload: The parsed custom webhook body.

    Returns:
        A normalized event.
    """
    severity = _parse_severity(payload.severity)

    return NormalizedEvent(
        tenant_id=tenant_id,
        source=EventSource.CUSTOM,
        severity=severity,
        title=payload.title or "Custom Alert",
        body=payload.body or "",
        tags=payload.tags,
        raw_payload=payload.metadata,
    )


# ── Severity Mapping Helpers ──────────────────────────────────

def _map_datadog_severity(alert_type: str) -> EventSeverity:
    """Map Datadog alert_type to VCE severity."""
    mapping = {
        "error": EventSeverity.CRITICAL,
        "warning": EventSeverity.WARNING,
        "info": EventSeverity.INFO,
        "success": EventSeverity.INFO,
    }
    return mapping.get(alert_type.lower(), EventSeverity.WARNING)


def _map_cloudwatch_severity(state_value: str) -> EventSeverity:
    """Map CloudWatch alarm state to VCE severity."""
    mapping = {
        "ALARM": EventSeverity.CRITICAL,
        "INSUFFICIENT_DATA": EventSeverity.WARNING,
        "OK": EventSeverity.INFO,
    }
    return mapping.get(state_value, EventSeverity.WARNING)


def _parse_severity(severity_str: str) -> EventSeverity:
    """Parse a severity string into an EventSeverity enum."""
    try:
        return EventSeverity(severity_str.lower())
    except ValueError:
        return EventSeverity.WARNING
