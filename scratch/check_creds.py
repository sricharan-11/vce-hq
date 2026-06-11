import sqlite3
import os
from vce_hq.config import settings

def check_creds():
    # Try the default tenant first
    tenant_id = "tenant-123"
    db_path = settings.tenant_db_path(tenant_id)
    print(f"Checking DB: {db_path}")
    if not os.path.exists(db_path):
        print("DB does not exist.")
        return

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    rows = conn.execute("SELECT name, provider FROM credentials").fetchall()
    print(f"Found {len(rows)} credentials:")
    for row in rows:
        print(f"  - {row['name']} ({row['provider']})")
    conn.close()

if __name__ == "__main__":
    check_creds()
