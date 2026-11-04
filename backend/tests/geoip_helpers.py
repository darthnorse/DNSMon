import asyncio
import shutil
from pathlib import Path

from backend import geoip as geoip_module
from backend.geoip import ASN_EDITION, CITY_EDITION
from backend.models import GeoipSettings

KEY = "abcSECRETkey123"
DATA = Path(__file__).parent / "data"
FIXTURES = {CITY_EDITION: DATA / "GeoIP2-City-Test.mmdb", ASN_EDITION: DATA / "GeoLite2-ASN-Test.mmdb"}


async def background_settled():
    await asyncio.gather(*geoip_module._background_tasks)


def refuse_unlink(self, missing_ok=False):
    raise PermissionError("nope")


async def seed_geoip(db_session, **fields):
    db_session.add(GeoipSettings(id=1, **fields))
    await db_session.commit()


async def stored_geoip(db_session):
    db_session.expire_all()
    return await db_session.get(GeoipSettings, 1)


def install_fixtures(service, *editions):
    service.directory.mkdir(parents=True)
    for edition in editions:
        shutil.copy(FIXTURES[edition], service.directory / f"{edition}.mmdb")
