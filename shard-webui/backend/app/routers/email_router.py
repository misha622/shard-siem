from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from typing import Dict
from app.auth import get_current_user
from app.database import get_email_settings, update_email_settings
from app.email_service import email_service, EmailMessage, EmailTemplate, EmailEvent, EmailPriority

router = APIRouter(prefix="/api/email", tags=["Email Notifications"])

class EmailSettingsUpdate(BaseModel):
    settings: Dict[str, bool]

class TestEmailRequest(BaseModel):
    email: str
    subject: str = "Test Email"
    message: str = "This is a test."

@router.get("/settings")
async def get_settings(current_user: dict = Depends(get_current_user)):
    settings = get_email_settings(current_user["id"])
    return {"settings": settings, "email_configured": email_service.enabled}

@router.put("/settings")
async def update_settings(data: EmailSettingsUpdate, current_user: dict = Depends(get_current_user)):
    update_email_settings(current_user["id"], data.settings)
    return {"message": "Settings updated", "settings": get_email_settings(current_user["id"])}

@router.get("/stats")
async def get_stats(current_user: dict = Depends(get_current_user)):
    return email_service.get_stats()

@router.post("/test")
async def send_test(data: TestEmailRequest, current_user: dict = Depends(get_current_user)):
    if not email_service.enabled:
        raise HTTPException(status_code=400, detail="Email not configured")
    msg = EmailMessage(to=[data.email], subject=data.subject, body_html=EmailTemplate.base_template(f"<p style='color:#fff'>{data.message}</p>", "Test"), event_type=EmailEvent.CUSTOM)
    ok = await email_service.send_now(msg)
    if ok: return {"message": "Sent"}
    raise HTTPException(status_code=500, detail="Failed")
