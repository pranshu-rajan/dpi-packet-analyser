from typing import List
from fastapi import APIRouter
from app.models.schemas import FilterRule

router = APIRouter(prefix="/api/rules", tags=["Rules"])

@router.get("/presets", response_model=List[FilterRule])
def get_rule_presets():
    """
    Returns curated enterprise and cyber policy presets.
    """
    return [
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
