from slowapi import Limiter
limiter = Limiter(key_func=lambda request: request.client.host if request.client else "unknown")
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from typing import Optional
from datetime import datetime
import csv, logging
from io import StringIO, BytesIO
from fastapi.responses import StreamingResponse
import openpyxl
from app.database import get_alerts, get_alert_by_id, block_alert_source
from app.auth import get_current_user

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/alerts", tags=["Alerts"])

@router.get("/")
@limiter.limit("100/minute")
async def list_alerts(request: Request, 
    alert_type: Optional[str] = None, severity: Optional[str] = None,
    source_ip: Optional[str] = None, destination_ip: Optional[str] = None,
    page: int = Query(default=1, ge=1), page_size: int = Query(default=50, ge=1, le=100),
    search: Optional[str] = None, company_id: Optional[int] = None,
    current_user: dict = Depends(get_current_user)
):
    effective_company = company_id if current_user["role"] == "admin" else current_user.get("company_id")
    params = {"alert_type": alert_type, "severity": severity, "source_ip": source_ip,
              "destination_ip": destination_ip, "page": page, "page_size": page_size, "search": search}
    alerts, total = get_alerts(params, effective_company)
    result = [{"id": a.id, "timestamp": __import__("datetime").datetime.fromtimestamp(a.timestamp).isoformat() if a.timestamp else None, "alert_type": a.attack_type,
               "severity": a.severity, "source_ip": a.src_ip, "destination_ip": a.dst_ip,
               "destination_port": a.dst_port, "protocol": a.protocol,
               "description": a.explanation, "threat_score": a.score * 100,
               "is_blocked": a.is_blocked, "company_id": a.company_id,
               "company_name": None} for a in alerts]  # company loaded separately
    return {"alerts": result, "total_count": total, "page": page, "page_size": page_size,
            "total_pages": (total + page_size - 1) // page_size}

@router.get("/export/csv")
async def export_csv(current_user: dict = Depends(get_current_user)):
    alerts, _ = get_alerts({}, current_user.get("company_id") if current_user["role"] != "admin" else None)
    output = StringIO()
    writer = csv.writer(output)
    writer.writerow(["ID","Timestamp","Type","Severity","Source IP","Dest IP","Description","Score","Company"])
    for a in alerts:
        writer.writerow([a.id, a.timestamp, a.attack_type, a.severity,
                        a.src_ip, a.dst_ip, a.explanation, a.score * 100,
                        a.company.name if a.company else ""])
    output.seek(0)
    return StreamingResponse(iter([output.getvalue()]), media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename=alerts_{datetime.utcnow():%Y%m%d_%H%M%S}.csv"})

@router.get("/export/excel")
async def export_excel(current_user: dict = Depends(get_current_user)):
    alerts, _ = get_alerts({}, current_user.get("company_id") if current_user["role"] != "admin" else None)
    wb = openpyxl.Workbook(); ws = wb.active; ws.title = "Alerts"
    ws.append(["ID","Timestamp","Type","Severity","Source IP","Dest IP","Description","Score","Company"])
    for a in alerts:
        ws.append([a.id, a.timestamp, a.attack_type, a.severity,
                   a.src_ip, a.dst_ip, a.explanation, a.score * 100,
                   a.company.name if a.company else ""])
    output = BytesIO(); wb.save(output); output.seek(0)
    return StreamingResponse(output, media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": f"attachment; filename=alerts_{datetime.utcnow():%Y%m%d_%H%M%S}.xlsx"})

@router.post("/{alert_id}/block")
async def block_alert(alert_id: int, current_user: dict = Depends(get_current_user)):
    blocked = block_alert_source(alert_id, current_user["username"])
    if not blocked: raise HTTPException(status_code=404, detail="Alert not found")
    return {"message": f"IP {blocked.ip_address} blocked", "block_id": blocked.id}
