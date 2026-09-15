import sys
from pathlib import Path

# Add backend to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent))

from sqlalchemy import create_engine, text
from app.models.db_models import Base, FirewallRuleModel
from app.database import init_db, SessionLocal

def test_supabase(db_url: str):
    print("=" * 60)
    print("TESTING SUPABASE POSTGRESQL CONNECTION")
    print("=" * 60)

    # Normalize url
    if db_url.startswith("postgres://"):
        db_url = db_url.replace("postgres://", "postgresql://", 1)

    print(f"\n1. Connecting to: {db_url.split('@')[-1] if '@' in db_url else 'Supabase'}...")
    
    try:
        engine = create_engine(db_url, pool_pre_ping=True)
        with engine.connect() as conn:
            version = conn.execute(text("SELECT version();")).fetchone()
            print(f"   [SUCCESS] Connected to PostgreSQL Server!")
            print(f"   PostgreSQL Version: {version[0][:40]}...")

        print("\n2. Initializing Database Tables & Seeding Rules...")
        Base.metadata.create_all(bind=engine)
        print("   [SUCCESS] Tables verified: captures, firewall_rules, threat_events, chat_messages")

        from sqlalchemy.orm import sessionmaker
        TestSession = sessionmaker(bind=engine)
        session = TestSession()

        # Check existing rules or seed
        count = session.query(FirewallRuleModel).count()
        if count == 0:
            print("   Seeding default rules into Supabase...")
            from app.api.rules import DEFAULT_PRESETS
            for p in DEFAULT_PRESETS:
                session.add(FirewallRuleModel(
                    id=p.id,
                    rule_type=p.type,
                    pattern_value=p.value,
                    action="drop",
                    is_enabled=p.enabled,
                    description=p.description or ""
                ))
            session.commit()
            count = session.query(FirewallRuleModel).count()

        print(f"   [SUCCESS] Firewall Rules in Supabase: {count}")
        session.close()

        print("\n" + "=" * 60)
        print("ALL CHECKS PASSED: Supabase database is LIVE and ready!")
        print("=" * 60)

    except Exception as e:
        print(f"\n[FAILED] Could not connect to Supabase: {e}")
        print("\nCommon fixes:")
        print("  1. Check if the password in the URI is correct.")
        print("  2. If your password has special characters (like @, #, %), URL-encode them.")
        print("  3. Ensure you selected Session Pooler (port 5432).")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python backend/test_supabase_connection.py \"postgresql://postgres.xxx:password@aws-0-xx.pooler.supabase.co:5432/postgres\"")
        sys.exit(1)
    test_supabase(sys.argv[1])
