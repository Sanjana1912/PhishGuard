# app/routers/scan.py
# Handles POST /api/scan
from app.db.scan_serialize import enrich_scan_ml_fields
from app.ml.ml_utils import normalize_ml_result
from app.ml.predictor import predict
from app.core.security import get_current_user
from app.db.mongo import save_scan
from app.services.typosquatch import check_typosquatting
from app.services.deobfuscator import deobfuscate_url
from app.services.whois_dns import get_whois_dns
from app.services.urlhaus import check_urlhaus
from app.services.virustotal import check_virustotal
from app.core.risk_engine import calculate_risk
from app.models.schemas import ScanRequest
import asyncio
import uuid
from datetime import datetime, timezone
from slowapi import Limiter
from slowapi.util import get_remote_address
from fastapi import APIRouter, Request, Depends
from app.core.security import get_current_user
import copy


router = APIRouter()
limiter = Limiter(key_func=get_remote_address)


@router.post("/scan")
@limiter.limit("10/minute")
async def scan_url(
    request: Request,
    body: ScanRequest,
    #current_user: dict = Depends(get_current_user),
):
    """Main scan endpoint — ML + CTI pipeline. Returns plain JSON with guaranteed ML fields."""
    clean_url = await deobfuscate_url(body.url)

    # ML runs on original URL (features) and cleaned URL — use body.url for consistency
    ml_result = normalize_ml_result(predict(body.url))

    vt_result, urlhaus_result, whois_result, typo_result = await asyncio.gather(
        check_virustotal(clean_url),
        check_urlhaus(clean_url),
        get_whois_dns(body.url),
        check_typosquatting(body.url),
    )

    risk_data = calculate_risk(
        vt=vt_result,
        urlhaus=urlhaus_result,
        whois=whois_result,
        typo=typo_result,
        ml=ml_result,
    )

    scan_id = str(uuid.uuid4())
    ready = ml_result["ml_ready"]
    ml_confidence_val = ml_result["ml_confidence"] if ready else None
    ml_score_val = ml_result["ml_score"] if ready else None
    ml_prediction_val = (
        ml_result["ml_prediction"]
        if ready and ml_result["ml_prediction"] not in ("unknown",)
        else None
    )

    payload = {
        "scan_id": scan_id,
        "url": body.url,
        "risk_score": risk_data["score"],
        "risk_level": risk_data["level"],
        "prediction": risk_data["prediction"],
        "explanation": risk_data["explanation"],
        "ml_confidence": ml_confidence_val,
        "ml_score": ml_score_val,
        "ml_prediction": ml_prediction_val,
        "ml_ready": ready,
        "features": whois_result,
        "threat_intel": {
            "ml": ml_result,
            "virustotal": vt_result,
            "urlhaus": urlhaus_result,
            "typosquatting": typo_result,
        },
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    payload = enrich_scan_ml_fields(payload)
    # await save_scan(payload)
    await save_scan(copy.deepcopy(payload))
    return payload
