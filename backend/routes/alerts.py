"""
Alert rules routes
"""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from typing import List

from ..database import get_db
from ..models import AlertRule, User
from ..schemas import AlertRuleCreate, AlertRuleUpdate, AlertRuleResponse
from ..auth import get_current_user, require_admin
from ..service import get_service


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
    return [AlertRuleResponse.model_validate(r) for r in rules]


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

    service = get_service()
    await service.alert_engine.invalidate_cache(db_rule.id)

    return AlertRuleResponse.model_validate(db_rule)


@router.put("/{rule_id}", response_model=AlertRuleResponse)
async def update_alert_rule(
    rule_id: int,
    rule_update: AlertRuleUpdate,
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

    await db.commit()
    await db.refresh(db_rule)

    service = get_service()
    await service.alert_engine.invalidate_cache(rule_id)

    return AlertRuleResponse.model_validate(db_rule)


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

    service = get_service()
    await service.alert_engine.invalidate_cache(rule_id)

    return {"message": "Alert rule deleted"}
