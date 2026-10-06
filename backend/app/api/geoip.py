"""GeoIP (country) resolution and settings endpoints."""
from fastapi import APIRouter, Depends, Query

from ..geoip import (
    download_database,
    geo_resolver,
    get_geo_settings,
    update_geo_settings,
)
from .deps import require_user
from .schemas import GeoIpSettings

router = APIRouter(prefix="/api", tags=["geoip"])

_MAX_IPS = 200


@router.get("/geo")
def lookup_countries(
    ips: str = Query(default="", description="Comma-separated list of IP addresses"),
    user: str = Depends(require_user),
) -> dict:
    values = [item.strip() for item in ips.split(",") if item.strip()][:_MAX_IPS]
    return {"items": geo_resolver.resolve(values)}


@router.get("/settings/geoip")
def read_geoip_settings(user: str = Depends(require_user)) -> dict:
    return get_geo_settings(mask_key=True)


@router.put("/settings/geoip")
def write_geoip_settings(
    payload: GeoIpSettings, user: str = Depends(require_user)
) -> dict:
    return update_geo_settings(payload.model_dump(exclude_none=True))


@router.get("/settings/geoip/status")
def geoip_status(user: str = Depends(require_user)) -> dict:
    return geo_resolver.status()


@router.post("/settings/geoip/update")
def geoip_update(user: str = Depends(require_user)) -> dict:
    return download_database()
