"""Pydantic schemas for webhook payloads.

Each supported source (Datadog, CloudWatch, Custom) has its own
request schema. These are intentionally permissive — we accept
the raw payload and normalize it downstream.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class DatadogWebhookPayload(BaseModel):
    """Datadog alert webhook payload.

    Reference: https://docs.datadoghq.com/integrations/webhooks/

    Datadog sends a variety of fields; we capture the essentials
    and preserve the rest in ``raw``.
    """
    title: str = ""
    body: str = ""
    alert_type: str = ""  # "error", "warning", "info", "success"
    alert_id: str = ""
    event_type: str = ""
    tags: str = ""  # Comma-separated tag string
    priority: str = ""
    hostname: str = ""
    raw: dict[str, Any] = Field(default_factory=dict)


class CloudWatchWebhookPayload(BaseModel):
    """AWS CloudWatch alarm notification via SNS → webhook.

    The SNS message body is typically a JSON string containing the
    alarm details. We parse the outer SNS envelope here.
    """
    Type: str = ""  # "Notification"
    MessageId: str = ""
    TopicArn: str = ""
    Subject: str = ""
    Message: str = ""  # JSON string of the actual alarm
    Timestamp: str = ""
    raw: dict[str, Any] = Field(default_factory=dict)


class CustomWebhookPayload(BaseModel):
    """Generic JSON webhook payload for user-defined sources.

    This is the most permissive schema — accepts any JSON body
    with optional structured fields.
    """
    title: str = ""
    body: str = ""
    severity: str = "info"
    tags: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)
