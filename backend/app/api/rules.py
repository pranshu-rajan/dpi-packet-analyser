import uuid
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.db_models import FirewallRuleModel
from app.models.schemas import FilterRule, CreateRuleRequest

router = APIRouter(prefix="/api/rules", tags=["Rules"])

DEFAULT_PRESETS = [
    FilterRule(
        id="preset-yt",
        type="app",
        value="YouTube",
        enabled=False,
        description="Block video streaming bandwidth consumption"
    ),
    FilterRule(
        id="preset-tk",
        type="app",
        value="TikTok",
        enabled=False,
        description="Enforce enterprise social media compliance policy"
    ),
    FilterRule(
        id="preset-fb",
        type="app",
        value="Facebook",
        enabled=False,
        description="Block social networking trackers"
    ),
    FilterRule(
        id="preset-sp",
        type="domain",
        value="spotify.com",
        enabled=False,
        description="Restrict audio streaming bandwidth"
    ),
    FilterRule(
        id="preset-ip",
        type="ip",
        value="192.168.1.50",
        enabled=False,
        description="Contain suspicious test host IP"
    ),
    FilterRule(
        id="preset-tg",
        type="app",
        value="Telegram",
        enabled=False,
        description="Block unmonitored encrypted messaging"
    )
]

def model_to_schema(m: FirewallRuleModel) -> FilterRule:
    return FilterRule(
        id=m.id,
        type=m.rule_type,
        value=m.pattern_value,
        enabled=m.is_enabled,
        description=m.description or ""
    )

@router.get("", response_model=List[FilterRule])
def get_all_rules(db: Session = Depends(get_db)):
    """
    Retrieves all persistent firewall rules from the database.
    """
    db_rules = db.query(FirewallRuleModel).order_by(FirewallRuleModel.created_at.asc()).all()
    if not db_rules:
        # Seed default presets if empty
        for p in DEFAULT_PRESETS:
            r = FirewallRuleModel(
                id=p.id,
                rule_type=p.type,
                pattern_value=p.value,
                action="drop",
                is_enabled=p.enabled,
                description=p.description or ""
            )
            db.add(r)
        db.commit()
        db_rules = db.query(FirewallRuleModel).order_by(FirewallRuleModel.created_at.asc()).all()

    return [model_to_schema(r) for r in db_rules]

@router.get("/presets", response_model=List[FilterRule])
def get_rule_presets():
    """
    Returns curated enterprise and cyber policy presets.
    """
    return DEFAULT_PRESETS

@router.post("", response_model=FilterRule)
def create_rule(req: CreateRuleRequest, db: Session = Depends(get_db)):
    """
    Creates and persists a new custom firewall rule.
    """
    rule_id = f"rule-{uuid.uuid4().hex[:8]}"
    db_rule = FirewallRuleModel(
        id=rule_id,
        rule_type=req.type,
        pattern_value=req.value,
        action=req.action,
        is_enabled=req.enabled,
        description=req.description or ""
    )
    db.add(db_rule)
    db.commit()
    db.refresh(db_rule)
    return model_to_schema(db_rule)

@router.post("/bulk", response_model=List[FilterRule])
def bulk_sync_rules(rules: List[FilterRule], db: Session = Depends(get_db)):
    """
    Synchronizes an entire list of rules from the frontend into the database.
    """
    existing = {r.id: r for r in db.query(FirewallRuleModel).all()}
    
    for rule_data in rules:
        if rule_data.id in existing:
            m = existing[rule_data.id]
            m.rule_type = rule_data.type
            m.pattern_value = rule_data.value
            m.is_enabled = rule_data.enabled
            m.description = rule_data.description or ""
        else:
            new_rule = FirewallRuleModel(
                id=rule_data.id,
                rule_type=rule_data.type,
                pattern_value=rule_data.value,
                action="drop",
                is_enabled=rule_data.enabled,
                description=rule_data.description or ""
            )
            db.add(new_rule)
            
    db.commit()
    all_rules = db.query(FirewallRuleModel).order_by(FirewallRuleModel.created_at.asc()).all()
    return [model_to_schema(r) for r in all_rules]

@router.patch("/{rule_id}/toggle", response_model=FilterRule)
def toggle_rule(rule_id: str, db: Session = Depends(get_db)):
    """
    Toggles a firewall rule between enabled and disabled state in the database.
    """
    db_rule = db.query(FirewallRuleModel).filter(FirewallRuleModel.id == rule_id).first()
    if not db_rule:
        raise HTTPException(status_code=404, detail=f"Rule {rule_id} not found")

    db_rule.is_enabled = not db_rule.is_enabled
    db.commit()
    db.refresh(db_rule)
    return model_to_schema(db_rule)

@router.delete("/{rule_id}")
def delete_rule(rule_id: str, db: Session = Depends(get_db)):
    """
    Deletes a firewall rule from the database.
    """
    db_rule = db.query(FirewallRuleModel).filter(FirewallRuleModel.id == rule_id).first()
    if not db_rule:
        raise HTTPException(status_code=404, detail=f"Rule {rule_id} not found")

    db.delete(db_rule)
    db.commit()
    return {"status": "success", "deleted_rule_id": rule_id}
