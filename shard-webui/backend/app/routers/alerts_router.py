from fastapi import APIRouter, Depends, HTTPException, Query, status
from typing import Optional, List
from datetime import datetime
from app.schemas import AlertResponse, AlertListResponse, BlockIPRequest
from app.database import db
from app.auth import get_current_user, require_role
from app.models import UserRole, SeverityLevel, AlertType
from app.eventbus import eventbus
import logging
import csv
from io import StringIO
from fastapi.responses import StreamingResponse
import openpyxl
from io import BytesIO

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/alerts", tags=["Alerts"])


@router.get("/", response_model=AlertListResponse)
async def get_alerts(
        alert_type: Optional[AlertType] = None,
        severity: Optional[SeverityLevel] = None,
        source_ip: Optional[str] = None,
        destination_ip: Optional[str] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        page: int = Query(default=1, ge=1),
        page_size: int = Query(default=50, ge=1, le=100),
        sort_by: str = Query(default="timestamp"),
        sort_order: str = Query(default="desc", pattern="^(asc|desc)$"),
        search: Optional[str] = None,
        current_user: dict = Depends(get_current_user)
):
    """
    Get alerts with filtering and pagination
    """
    query_params = {
        "alert_type": alert_type,
        "severity": severity,
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "start_time": start_time,
        "end_time": end_time,
        "page": page,
        "page_size": page_size,
        "sort_by": sort_by,
        "sort_order": sort_order
    }

    alerts, total_count = db.get_alerts(query_params)

    # Search in description if search query provided
    if search:
        alerts = [a for a in alerts if search.lower() in a.description.lower()
                  or search in a.source_ip or search in a.destination_ip]
        total_count = len(alerts)

    total_pages = (total_count + page_size - 1) // page_size

    return AlertListResponse(
        alerts=[AlertResponse(
            id=a.id,
            timestamp=a.timestamp,
            alert_type=a.alert_type,
            severity=a.severity,
            source_ip=a.source_ip,
            destination_ip=a.destination_ip,
            description=a.description,
            is_blocked=a.is_blocked,
            threat_score=a.threat_score
        ) for a in alerts],
        total_count=total_count,
        page=page,
        page_size=page_size,
        total_pages=total_pages
    )


@router.get("/{alert_id}", response_model=AlertResponse)
async def get_alert(
        alert_id: str,
        current_user: dict = Depends(get_current_user)
):
    """
    Get single alert by ID
    """
    alert = db.get_alert_by_id(alert_id)
    if not alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Alert not found"
        )

    return AlertResponse(
        id=alert.id,
        timestamp=alert.timestamp,
        alert_type=alert.alert_type,
        severity=alert.severity,
        source_ip=alert.source_ip,
        destination_ip=alert.destination_ip,
        description=alert.description,
        is_blocked=alert.is_blocked,
        threat_score=alert.threat_score
    )


@router.post("/{alert_id}/block")
async def block_alert_source(
        alert_id: str,
        current_user: dict = Depends(get_current_user)
):
    """
    Block the source IP of a specific alert
    """
    alert = db.get_alert_by_id(alert_id)
    if not alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Alert not found"
        )

    if alert.is_blocked:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="IP already blocked"
        )

    blocked = db.block_ip(
        ip_address=alert.source_ip,
        reason=f"Blocked from alert {alert_id}: {alert.alert_type}",
        blocked_by=current_user["username"]
    )

    # Notify event bus
    await eventbus.publish("firewall.blocked", {
        "ip": alert.source_ip,
        "reason": blocked.reason,
        "blocked_by": current_user["username"]
    })

    logger.info(f"IP {alert.source_ip} blocked by {current_user['username']}")

    return {
        "message": f"IP {alert.source_ip} blocked successfully",
        "block_id": blocked.id
    }


@router.get("/export/csv")
async def export_alerts_csv(
        alert_type: Optional[AlertType] = None,
        severity: Optional[SeverityLevel] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        current_user: dict = Depends(get_current_user)
):
    """
    Export alerts to CSV
    """
    query_params = {
        "alert_type": alert_type,
        "severity": severity,
        "start_time": start_time,
        "end_time": end_time,
        "page": 1,
        "page_size": 10000,  # Large page size for export
        "sort_by": "timestamp",
        "sort_order": "desc"
    }

    alerts, _ = db.get_alerts(query_params)

    # Create CSV
    output = StringIO()
    writer = csv.writer(output)
    writer.writerow(["ID", "Timestamp", "Type", "Severity", "Source IP", "Destination IP", "Description", "Blocked",
                     "Threat Score"])

    for alert in alerts:
        writer.writerow([
            alert.id,
            alert.timestamp.isoformat(),
            alert.alert_type,
            alert.severity,
            alert.source_ip,
            alert.destination_ip,
            alert.description,
            alert.is_blocked,
            alert.threat_score
        ])

    output.seek(0)

    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={
            "Content-Disposition": f"attachment; filename=alerts_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.csv"}
    )


@router.get("/export/excel")
async def export_alerts_excel(
        alert_type: Optional[AlertType] = None,
        severity: Optional[SeverityLevel] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        current_user: dict = Depends(get_current_user)
):
    """
    Export alerts to Excel
    """
    query_params = {
        "alert_type": alert_type,
        "severity": severity,
        "start_time": start_time,
        "end_time": end_time,
        "page": 1,
        "page_size": 10000,
        "sort_by": "timestamp",
        "sort_order": "desc"
    }

    alerts, _ = db.get_alerts(query_params)

    # Create Excel workbook
    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = "Alerts"

    # Headers
    headers = ["ID", "Timestamp", "Type", "Severity", "Source IP", "Destination IP", "Description", "Blocked",
               "Threat Score"]
    ws.append(headers)

    # Style headers
    for cell in ws[1]:
        cell.font = openpyxl.styles.Font(bold=True, color="FFFFFF")
        cell.fill = openpyxl.styles.PatternFill(start_color="00d4ff", end_color="00d4ff", fill_type="solid")

    # Add data
    for alert in alerts:
        ws.append([
            alert.id,
            alert.timestamp.isoformat(),
            alert.alert_type,
            alert.severity,
            alert.source_ip,
            alert.destination_ip,
            alert.description,
            str(alert.is_blocked),
            alert.threat_score
        ])

    # Adjust column widths
    for column in ws.columns:
        max_length = 0
        column_letter = column[0].column_letter
        for cell in column:
            try:
                if len(str(cell.value)) > max_length:
                    max_length = len(cell.value)
            except:
                pass
        adjusted_width = min(max_length + 2, 50)
        ws.column_dimensions[column_letter].width = adjusted_width

    # Save to bytes
    output = BytesIO()
    wb.save(output)
    output.seek(0)

    return StreamingResponse(
        output,
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={
            "Content-Disposition": f"attachment; filename=alerts_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.xlsx"}
    )