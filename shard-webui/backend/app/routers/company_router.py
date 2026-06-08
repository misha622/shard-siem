"""company_router API endpoints."""
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from typing import List, Optional
from app.database import SessionLocal, get_companies, get_company_by_id
from app.models import Company, User, Alert
from app.auth import get_current_user
from sqlalchemy import func
import logging

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/companies", tags=["Companies"])

class CompanyCreate(BaseModel):
    name: str = Field(..., min_length=2, max_length=100)
    ip_ranges: List[str] = []
    max_alerts_per_day: int = 10000

@router.get("/")
async def list_companies(current_user: dict = Depends(get_current_user)):
    if current_user["role"] == "admin":
        companies = get_companies()
    else:
        company = get_company_by_id(current_user["company_id"])
        companies = [company] if company else []
    db = SessionLocal()
    try:
        result = []
        for c in companies:
            user_count = db.query(User).filter(User.company_id == c.id).count()
            alert_count = db.query(Alert).filter(Alert.company_id == c.id, Alert.timestamp >= func.date('now')).count()
            result.append({"id": c.id, "name": c.name, "ip_ranges": c.ip_ranges, "is_active": c.is_active,
                          "user_count": user_count, "alert_count_today": alert_count})
        return result
    finally: db.close()

@router.post("/")
async def create_company(data: CompanyCreate, current_user: dict = Depends(get_current_user)):
    if current_user["role"] != "admin": raise HTTPException(status_code=403, detail="Admin access required")
    db = SessionLocal()
    try:
        if db.query(Company).filter(Company.name == data.name).first():
            raise HTTPException(status_code=400, detail="Company name already exists")
        company = Company(name=data.name, ip_ranges=data.ip_ranges, max_alerts_per_day=data.max_alerts_per_day)
        db.add(company); db.commit(); db.refresh(company)
        return {"id": company.id, "name": company.name, "message": "Company created"}
    finally: db.close()

@router.get("/{company_id}")
async def get_company(company_id: int, current_user: dict = Depends(get_current_user)):
    if current_user["role"] != "admin" and current_user.get("company_id") != company_id:
        raise HTTPException(status_code=403, detail="Access denied")
    company = get_company_by_id(company_id)
    if not company: raise HTTPException(status_code=404, detail="Company not found")
    return {"id": company.id, "name": company.name, "ip_ranges": company.ip_ranges, "is_active": company.is_active}
