from fastapi import APIRouter, Depends, HTTPException, Query
from typing import Optional
from datetime import datetime
from app.database import db
from app.auth import get_current_user
from app.models import SeverityLevel, AlertType
import csv, logging
from io import StringIO
from fastapi.responses import StreamingResponse
import openpyxl
from io import BytesIO

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/alerts", tags=["Alerts"])

@router.get("/")
async def get_alerts(
    alert_type: Optional[str] = None, severity: Optional[str] = None,
    source_ip: Optional[str] = None, destination_ip: Optional[str] = None,
    page: int = Query(default=1, ge=1), page_size: int = Query(default=50, ge=1, le=100),
    sort_by: str = Query(default="timestamp"), sort_order: str = Query(default="desc"),
    search: Optional[str] = None, current_user: dict = Depends(get_current_user)
):
    params = {"alert_type": alert_type, "severity": severity, "source_ip": source_ip,
              "destination_ip": destination_ip, "page": page, "page_size": page_size,
              "sort_by": sort_by, "sort_order": sort_order, "search": search}
    alerts, total = await db.get_alerts(params)
    return {
        "alerts": alerts, "total_count": total, "page": page,
        "page_size": page_size, "total_pages": (total + page_size - 1) // page_size
    }

@router.get("/export/csv")
async def export_csv(current_user: dict = Depends(get_current_user)):
    alerts, _ = await db.get_alerts({"page": 1, "page_size": 100000})
    output = StringIO()
    writer = csv.writer(output)
    writer.writerow(["ID","Timestamp","Type","Severity","Source IP","Dest IP","Description","Score"])
    for a in alerts:
        writer.writerow([a["id"],a["timestamp"],a["alert_type"],a["severity"],a["source_ip"],a["destination_ip"],a["description"],a["threat_score"]])
    output.seek(0)
    return StreamingResponse(iter([output.getvalue()]), media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename=alerts_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.csv"})

@router.get("/export/excel")
async def export_excel(current_user: dict = Depends(get_current_user)):
    alerts, _ = await db.get_alerts({"page": 1, "page_size": 100000})
    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = "Alerts"
    ws.append(["ID","Timestamp","Type","Severity","Source IP","Dest IP","Description","Score"])
    for a in alerts:
        ws.append([a["id"],a["timestamp"],a["alert_type"],a["severity"],a["source_ip"],a["destination_ip"],a["description"],a["threat_score"]])
    output = BytesIO()
    wb.save(output)
    output.seek(0)
    return StreamingResponse(output, media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": f"attachment; filename=alerts_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.xlsx"})

@router.post("/{alert_id}/block")
async def block_alert(alert_id: str, current_user: dict = Depends(get_current_user)):
    block_id = await db.block_alert_source(alert_id, current_user["username"])
    if not block_id:
        raise HTTPException(status_code=404, detail="Alert not found")
    return {"message": "IP blocked", "block_id": block_id}
