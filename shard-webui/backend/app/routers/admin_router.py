from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from database import SessionLocal, get_company_by_id
from models import Tenant, User
from auth import get_current_user
from sqlalchemy import func
import uuid, logging

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/admin", tags=["Super Admin"])

class CreateTenantRequest(BaseModel):
    name: str = Field(..., min_length=2, max_length=100)
    slug: str = Field(..., min_length=2, max_length=50, pattern=r"^[a-z0-9-]+$")
    plan: str = "trial"
    max_users: int = 10

@router.get("/tenants")
async def list_tenants(current_user: dict = Depends(get_current_user)):
    if current_user["role"] != "admin": raise HTTPException(status_code=403, detail="Admin access required")
    db = SessionLocal()
    try:
        tenants = db.query(Tenant).all()
        return [{"id": t.id, "name": t.name, "slug": t.slug, "plan": t.plan, "is_active": t.is_active} for t in tenants]
    finally: db.close()

@router.post("/tenants")
async def create_tenant(request: CreateTenantRequest, current_user: dict = Depends(get_current_user)):
    if current_user["role"] != "admin": raise HTTPException(status_code=403, detail="Admin access required")
    db = SessionLocal()
    try:
        if db.query(Tenant).filter(Tenant.slug == request.slug).first():
            raise HTTPException(status_code=400, detail="Slug already taken")
        tenant = Tenant(id=str(uuid.uuid4()), name=request.name, slug=request.slug, plan=request.plan, max_users=request.max_users)
        db.add(tenant); db.commit()
        return {"tenant_id": tenant.id, "message": f"Tenant '{request.name}' created"}
    finally: db.close()
