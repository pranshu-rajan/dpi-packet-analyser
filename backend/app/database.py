import logging
from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker
from app.config import DATABASE_URL

logger = logging.getLogger("dpi.database")

connect_args = {}
if DATABASE_URL.startswith("sqlite"):
    connect_args["check_same_thread"] = False
    engine = create_engine(DATABASE_URL, connect_args=connect_args)
else:
    # PostgreSQL / Supabase connection pooling
    engine = create_engine(
        DATABASE_URL,
        pool_pre_ping=True,
        pool_size=10,
        max_overflow=20
    )

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

def get_db():
    """
    FastAPI dependency that yields a scoped SQLAlchemy database session.
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def init_db():
    """
    Creates all tables if they do not exist and pre-seeds default firewall rules.
    """
    from app.models.db_models import CaptureRecord, FirewallRuleModel, ThreatEventModel, ChatMessageModel

    Base.metadata.create_all(bind=engine)
    logger.info("Database initialized successfully.")

    # Seed default rules if empty
    db = SessionLocal()
    try:
        rule_count = db.query(FirewallRuleModel).count()
        if rule_count == 0:
            default_rules = [
                FirewallRuleModel(
                    id="preset-yt",
                    rule_type="app",
                    pattern_value="YouTube",
                    action="drop",
                    is_enabled=False,
                    description="Block video streaming bandwidth consumption"
                ),
                FirewallRuleModel(
                    id="preset-tk",
                    rule_type="app",
                    pattern_value="TikTok",
                    action="drop",
                    is_enabled=False,
                    description="Enforce enterprise social media compliance policy"
                ),
                FirewallRuleModel(
                    id="preset-fb",
                    rule_type="app",
                    pattern_value="Facebook",
                    action="drop",
                    is_enabled=False,
                    description="Block social networking trackers"
                ),
                FirewallRuleModel(
                    id="preset-sp",
                    rule_type="domain",
                    pattern_value="spotify.com",
                    action="drop",
                    is_enabled=False,
                    description="Restrict audio streaming bandwidth"
                ),
                FirewallRuleModel(
                    id="preset-ip",
                    rule_type="ip",
                    pattern_value="192.168.1.50",
                    action="drop",
                    is_enabled=False,
                    description="Contain suspicious test host IP"
                ),
                FirewallRuleModel(
                    id="preset-tg",
                    rule_type="app",
                    pattern_value="Telegram",
                    action="drop",
                    is_enabled=False,
                    description="Block unmonitored encrypted messaging"
                )
            ]
            db.add_all(default_rules)
            db.commit()
            logger.info("Pre-seeded default firewall rules into database.")
    except Exception as e:
        logger.error(f"Error seeding default rules: {e}")
        db.rollback()
    finally:
        db.close()
