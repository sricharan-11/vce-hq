"""FinOps API endpoints for billing and token usage analysis."""

from typing import Annotated

from fastapi import APIRouter, Depends

from vce_hq.api.dependencies import get_stm, get_tenant_id
from vce_hq.db.short_term import ShortTermMemory

router = APIRouter(prefix="/finops", tags=["finops"])

@router.get("/token-usage")
def get_token_usage(
    tenant_id: Annotated[str, Depends(get_tenant_id)],
    stm: Annotated[ShortTermMemory, Depends(get_stm)],
):
    """Get aggregated LLM token usage for the tenant.
    
    Returns token usage grouped by time period (day, week, month, overall),
    with a breakdown by agent within each period.
    """
    return stm.get_token_usage_summary(tenant_id)
