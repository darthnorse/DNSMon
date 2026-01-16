"""
User management routes (admin only)
"""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from typing import List
import logging

from ..database import get_db
from ..models import User
from ..schemas import UserCreate, UserUpdate, UserResponse
from ..auth import hash_password, require_admin

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/users", tags=["users"])


@router.get("")
async def list_users(
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_admin)
) -> List[UserResponse]:
    """List all users (admin only)"""
    stmt = select(User).order_by(User.created_at.desc())
    result = await db.execute(stmt)
    users = result.scalars().all()
    return [UserResponse(**u.to_dict()) for u in users]


@router.post("")
async def create_user(
    data: UserCreate,
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(require_admin)
) -> UserResponse:
    """Create a new user (admin only)"""
    # Check if username exists
    stmt = select(User).where(User.username == data.username.lower())
    result = await db.execute(stmt)
    if result.scalar_one_or_none():
        raise HTTPException(status_code=400, detail="Username already exists")

    # Check if email exists (if provided)
    if data.email:
        stmt = select(User).where(User.email == data.email.lower())
        result = await db.execute(stmt)
        if result.scalar_one_or_none():
            raise HTTPException(status_code=400, detail="Email already exists")

    user = User(
        username=data.username.lower(),
        email=data.email.lower() if data.email else None,
        display_name=data.display_name,
        password_hash=hash_password(data.password) if data.password else None,
        is_admin=data.is_admin,
        is_active=True
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)

    logger.info(f"Admin '{admin.username}' created user '{user.username}'")
    return UserResponse(**user.to_dict())


@router.put("/{user_id}")
async def update_user(
    user_id: int,
    data: UserUpdate,
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(require_admin)
) -> UserResponse:
    """Update a user (admin only)"""
    stmt = select(User).where(User.id == user_id)
    result = await db.execute(stmt)
    user = result.scalar_one_or_none()

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # Prevent admin from demoting themselves
    if user.id == admin.id and data.is_admin is False:
        raise HTTPException(status_code=400, detail="Cannot remove your own admin privileges")

    if data.email is not None:
        user.email = data.email.lower() if data.email else None
    if data.display_name is not None:
        user.display_name = data.display_name
    if data.password:
        user.password_hash = hash_password(data.password)
    if data.is_active is not None:
        user.is_active = data.is_active
    if data.is_admin is not None:
        user.is_admin = data.is_admin

    await db.commit()
    await db.refresh(user)

    logger.info(f"Admin '{admin.username}' updated user '{user.username}'")
    return UserResponse(**user.to_dict())


@router.delete("/{user_id}")
async def delete_user(
    user_id: int,
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(require_admin)
):
    """Delete a user (admin only)"""
    if user_id == admin.id:
        raise HTTPException(status_code=400, detail="Cannot delete your own account")

    stmt = select(User).where(User.id == user_id)
    result = await db.execute(stmt)
    user = result.scalar_one_or_none()

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    username = user.username
    await db.delete(user)
    await db.commit()

    logger.info(f"Admin '{admin.username}' deleted user '{username}'")
    return {"message": f"User '{username}' deleted"}
