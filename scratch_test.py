import asyncio
import sqlite3
import os
import sys

# Add src to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../../../../src')))

from vce_hq.agents.graph import build_analysis_graph
from vce_hq.db.short_term import ShortTermMemory
from vce_hq.env.discovery import discover_environment

async def main():
    conn = sqlite3.connect(':memory:', check_same_thread=False)
    stm = ShortTermMemory(conn)
    env_profile = discover_environment()
    
    graph = build_analysis_graph(conn, env_profile)
    
    print("Running query...")
    async for step in graph.astream({
        "tenant_id": "test",
        "session_id": "new_session_123",
        "user_query": "RUn a cloud monitoring check and let me know thwe used services in last 4 days",
    }, config={"recursion_limit": 10}):
        for node, state in step.items():
            print(f"--- Node: {node} ---")
            if node == "intent_analyzer_node":
                print(f"Intent: {state.get('intent_status')}")
            elif node == "router_node":
                print(f"Router Theory: {state.get('router_theory')}")
                print(f"Router Instruction: {state.get('router_instruction')}")
                print(f"Delegate to: {state.get('delegate_to')}")
            elif "analysis" in node or "review" in node:
                print("Finished agent node")

if __name__ == "__main__":
    asyncio.run(main())
