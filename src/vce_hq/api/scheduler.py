"""Background job scheduler for automated agent execution.

Configures APScheduler to run the FinOps Agent every hour to detect
consumption anomalies and optimize costs across all tenants, without
any user interaction.
"""

import asyncio
import logging
import os
import sqlite3
from pathlib import Path

from apscheduler.schedulers.asyncio import AsyncIOScheduler

from vce_hq.agents.graph import build_agent_graph
from vce_hq.config import settings
from vce_hq.db.connection import create_connection
from vce_hq.db.models import AgentType, ConversationTurn, Session
from vce_hq.db.short_term import ShortTermMemory
from vce_hq.discovery.probe import get_environment_profile
from vce_hq.embeddings.service import EmbeddingService
from vce_hq.vault.manager import CredentialManager

logger = logging.getLogger(__name__)


async def run_finops_analysis(job_type: str, query: str) -> None:
    """Run the FinOps analysis for all active tenants.
    
    Args:
        job_type: "HOURLY", "DAILY", or "MONTHLY".
        query: The specific instruction for the FinOps agent.
    """
    logger.info("Scheduler: Starting %s FinOps analysis cycle across all tenants", job_type)
    
    data_dir = Path(settings.data_dir)
    if not data_dir.exists():
        logger.warning("Scheduler: Data directory does not exist, skipping.")
        return
        
    # Discover tenants by looking at .db files (since isolation is per-db)
    tenant_files = list(data_dir.glob("*.db"))
    
    for db_path in tenant_files:
        tenant_id = db_path.stem
        logger.info("Scheduler: Running automated %s FinOps report for tenant '%s'", job_type, tenant_id)
        
        try:
            conn = create_connection(tenant_id)
            stm = ShortTermMemory(conn)
            
            # Setup dependencies
            embedding_service = EmbeddingService(conn)
            credential_manager = CredentialManager(tenant_id, conn)
            
            # We don't cache the profile here; we want live discovery for the hourly report
            env_profile = await get_environment_profile()
            
            # Create a synthetic session
            session = Session(tenant_id=tenant_id)
            stm.create_session(session)
            stm.update_session_status(session.session_id, session.status.ANALYZING)
            
            # Persist synthetic user query
            stm.add_turn(ConversationTurn(
                session_id=session.session_id,
                agent=AgentType.ROUTER,
                content=f"[SYSTEM SCHEDULED FINOPS {job_type} EVENT]: {query}",
            ))
            
            graph = build_agent_graph(
                conn=conn,
                embedding_service=embedding_service,
                credential_manager=credential_manager,
                env_profile=env_profile,
            )
            
            initial_state = {
                "tenant_id": tenant_id,
                "session_id": session.session_id,
                "user_query": query,
            }
            
            # Execute graph
            result = await graph.ainvoke(initial_state)
            
            if "error" in result:
                logger.error("Scheduler: Graph execution failed for tenant '%s': %s", tenant_id, result["error"])
                stm.update_session_status(session.session_id, session.status.FAILED)
            else:
                logger.info("Scheduler: Successfully generated FinOps report for tenant '%s'", tenant_id)
                stm.update_session_status(session.session_id, session.status.COMPLETED)
                
            conn.close()
            
        except Exception as e:
            logger.error("Scheduler: Unexpected error running FinOps for tenant '%s': %s", tenant_id, e)


def start_scheduler() -> AsyncIOScheduler:
    """Initialize and start the background scheduler.
    
    Returns:
        The started APScheduler instance.
    """
    scheduler = AsyncIOScheduler()
    
    # 1. Hourly Job: Spike detection and abusive usage
    scheduler.add_job(
        run_finops_analysis,
        "interval",
        hours=1,
        id="finops_hourly_job",
        kwargs={
            "job_type": "HOURLY",
            "query": "Perform the automated hourly FinOps analysis: Check for abrupt spikes and abusive usage levels."
        },
        replace_existing=True,
    )
    
    # 2. Daily Job: Waste cleanup, bill differences, top consumers
    scheduler.add_job(
        run_finops_analysis,
        "interval",
        days=1,
        id="finops_daily_job",
        kwargs={
            "job_type": "DAILY",
            "query": "Perform the automated daily FinOps analysis: Analyze component-level bill differences, map against workload effectiveness, identify idle/underutilized resources for cleanup, and deeply analyze top 5 consumers."
        },
        replace_existing=True,
    )
    
    # 3. Monthly Job: Optimization push and budget recalibration
    # Runs roughly every 30 days
    scheduler.add_job(
        run_finops_analysis,
        "interval",
        days=30,
        id="finops_monthly_job",
        kwargs={
            "job_type": "MONTHLY",
            "query": "Perform the automated monthly FinOps analysis: Push for architectural optimization by investigating cost-saving alternatives, and recalibrate actual usage against ideal PnL budgets."
        },
        replace_existing=True,
    )
    
    scheduler.start()
    logger.info("Scheduler: APScheduler started with Hourly, Daily, and Monthly FinOps jobs.")
    return scheduler
