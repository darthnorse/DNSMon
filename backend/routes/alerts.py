"""
Alert rules routes
"""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from typing import List
from datetime import datetime, timezone

from ..database import get_db
from ..models import AlertRule, User
from ..schemas import AlertRuleCreate, AlertRuleResponse
from ..auth import get_current_user, require_admin
from ..service import get_service
from ..utils import ensure_utc


router = APIRouter(prefix="/api/alert-rules", tags=["alerts"])


@router.get("", response_model=List[AlertRuleResponse])
async def get_alert_rules(
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user)
):
    """Get all alert rules"""
    stmt = select(AlertRule).order_by(AlertRule.created_at.desc())
    result = await db.execute(stmt)
    rules = result.scalars().all()

    return [AlertRuleResponse(
        id=r.id,
        name=r.name,
        description=r.description,
        domain_pattern=r.domain_pattern,
        client_ip_pattern=r.client_ip_pattern,
        client_hostname_pattern=r.client_hostname_pattern,
        exclude_domains=r.exclude_domains,
        cooldown_minutes=r.cooldown_minutes,
        enabled=r.enabled,
        created_at=ensure_utc(r.created_at),
        updated_at=ensure_utc(r.updated_at)
    ) for r in rules]


@router.post("", response_model=AlertRuleResponse)
async def create_alert_rule(
    rule: AlertRuleCreate,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_admin)
):
    """Create a new alert rule"""
    db_rule = AlertRule(**rule.model_dump())
    db.add(db_rule)
    await db.commit()
    await db.refresh(db_rule)

    # Invalidate pattern cache for new rule
    service = get_service()
    await service.alert_engine.invalidate_cache(db_rule.id)

    return AlertRuleResponse(
        id=db_rule.id,
        name=db_rule.name,
        description=db_rule.description,
        domain_pattern=db_rule.domain_pattern,
        client_ip_pattern=db_rule.client_ip_pattern,
        client_hostname_pattern=db_rule.client_hostname_pattern,
        exclude_domains=db_rule.exclude_domains,
        cooldown_minutes=db_rule.cooldown_minutes,
        enabled=db_rule.enabled,
        created_at=ensure_utc(db_rule.created_at),
        updated_at=ensure_utc(db_rule.updated_at)
    )


@router.put("/{rule_id}", response_model=AlertRuleResponse)
async def update_alert_rule(
    rule_id: int,
    rule_update: AlertRuleCreate,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_admin)
):
    """Update an existing alert rule"""
    stmt = select(AlertRule).where(AlertRule.id == rule_id)
    result = await db.execute(stmt)
    db_rule = result.scalar_one_or_none()

    if not db_rule:
        raise HTTPException(status_code=404, detail="Alert rule not found")

    update_data = rule_update.model_dump(exclude_unset=True)
    for key, value in update_data.items():
        if key not in ('id', 'created_at', 'updated_at'):
            setattr(db_rule, key, value)

    db_rule.updated_at = datetime.now(timezone.utc)

    await db.commit()
    await db.refresh(db_rule)

    # Invalidate pattern cache for updated rule
    service = get_service()
    await service.alert_engine.invalidate_cache(rule_id)

    return AlertRuleResponse(
        id=db_rule.id,
        name=db_rule.name,
        description=db_rule.description,
        domain_pattern=db_rule.domain_pattern,
        client_ip_pattern=db_rule.client_ip_pattern,
        client_hostname_pattern=db_rule.client_hostname_pattern,
        exclude_domains=db_rule.exclude_domains,
        cooldown_minutes=db_rule.cooldown_minutes,
        enabled=db_rule.enabled,
        created_at=ensure_utc(db_rule.created_at),
        updated_at=ensure_utc(db_rule.updated_at)
    )


@router.delete("/{rule_id}")
async def delete_alert_rule(
    rule_id: int,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_admin)
):
    """Delete an alert rule"""
    stmt = select(AlertRule).where(AlertRule.id == rule_id)
    result = await db.execute(stmt)
    db_rule = result.scalar_one_or_none()

    if not db_rule:
        raise HTTPException(status_code=404, detail="Alert rule not found")

    await db.delete(db_rule)
    await db.commit()

    # Invalidate pattern cache for deleted rule
    service = get_service()
    await service.alert_engine.invalidate_cache(rule_id)

    return {"message": "Alert rule deleted"}
