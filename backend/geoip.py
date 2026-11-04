import asyncio
import gzip
import ipaddress
import logging
import os
import shutil
import tarfile
import zlib
from datetime import timedelta
from pathlib import Path, PurePosixPath
from typing import Callable, Iterable

import httpx
import maxminddb
from maxminddb.reader import Reader

from .database import async_session_maker
from .models import GeoipSettings, utcnow
from .schemas import GeoInfo

logger = logging.getLogger(__name__)

GEOIP_ROW_ID = 1
REFRESH_INTERVAL_HOURS = 24
CITY_EDITION = 'GeoLite2-City'
ASN_EDITION = 'GeoLite2-ASN'
# Substrings, not exact names: MaxMind's test City database is typed GeoIP2-City.
EDITION_TYPES = {CITY_EDITION: 'City', ASN_EDITION: 'ASN'}
EDITIONS = tuple(EDITION_TYPES)
DOWNLOAD_URL = 'https://download.maxmind.com/geoip/databases/{edition}/download?suffix=tar.gz'

# City is roughly 70-100 MB uncompressed. Room to grow, but a bad response can't fill the volume.
MAX_DOWNLOAD_BYTES = 300 * 1024 * 1024
MAX_MMDB_BYTES = 500 * 1024 * 1024
MAX_ARCHIVE_MEMBERS = 100
HTTP_TIMEOUT = httpx.Timeout(30.0, connect=10.0)
# Clearing credentials waits on the refresh lock, so a stalling download must not hold it forever.
EDITION_TIMEOUT_SECONDS = 900
LAST_ERROR_MAX_LENGTH = GeoipSettings.last_error.type.length


class _RefreshFailure(Exception):
    """Carries a message we wrote. Text from httpx must never reach one: its errors
    quote the full URL, which after a redirect holds a presigned signature."""


def _describe_status(code: int) -> str:
    if code == 401:
        return f'MaxMind rejected the credentials (HTTP {code})'
    if code == 429:
        return f'MaxMind rate limit reached (HTTP {code})'
    return f'HTTP {code}'


def _is_unsafe_member_name(name: str) -> bool:
    path = PurePosixPath(name.replace('\\', '/'))
    return path.is_absolute() or '..' in path.parts


def _extract_mmdb(archive: Path, dest: Path) -> None:
    try:
        with tarfile.open(archive, 'r:gz') as tar:
            found = None
            for count, member in enumerate(tar, start=1):
                if count > MAX_ARCHIVE_MEMBERS:
                    raise _RefreshFailure('Archive invalid: too many members')
                if _is_unsafe_member_name(member.name):
                    raise _RefreshFailure('Archive invalid: unsafe member path')
                if member.name.endswith('.mmdb'):
                    if found is not None:
                        raise _RefreshFailure('Archive invalid: more than one .mmdb member')
                    found = member
            if found is None:
                raise _RefreshFailure('Archive invalid: no .mmdb member')
            if not found.isreg():
                raise _RefreshFailure('Archive invalid: .mmdb member is not a regular file')
            if found.size > MAX_MMDB_BYTES:
                raise _RefreshFailure(
                    f'Archive invalid: database larger than {MAX_MMDB_BYTES // (1024 * 1024)} MB')
            with tar.extractfile(found) as source, dest.open('wb') as out:
                shutil.copyfileobj(source, out)
    except (tarfile.TarError, EOFError, gzip.BadGzipFile, zlib.error):
        raise _RefreshFailure('Archive invalid: not a readable tar.gz') from None


def _open_checked(path: Path, edition: str) -> Reader:
    reader = maxminddb.open_database(path)
    if EDITION_TYPES[edition] not in reader.metadata().database_type:
        reader.close()
        raise maxminddb.InvalidDatabaseError('database type does not match the edition')
    return reader


def _unpack_and_open(archive: Path, tmp: Path, edition: str) -> Reader:
    _extract_mmdb(archive, tmp)
    try:
        return _open_checked(tmp, edition)
    except (maxminddb.InvalidDatabaseError, ValueError):
        raise _RefreshFailure(f'Archive invalid: not a {edition} database') from None


async def _download(client: httpx.AsyncClient, url: str, dest: Path) -> None:
    # Raw bytes with identity: a .tar.gz served with Content-Encoding: gzip must reach
    # tarfile still compressed, and the cap must count what actually lands on disk.
    async with client.stream('GET', url, headers={'Accept-Encoding': 'identity'}) as response:
        if not response.is_success:
            raise _RefreshFailure(_describe_status(response.status_code))
        received = 0
        with dest.open('wb') as out:
            async for chunk in response.aiter_raw():
                received += len(chunk)
                if received > MAX_DOWNLOAD_BYTES:
                    raise _RefreshFailure(
                        f'Download larger than {MAX_DOWNLOAD_BYTES // (1024 * 1024)} MB')
                out.write(chunk)


def _city_fields(record: dict) -> dict:
    country = record.get('country') or record.get('registered_country') or {}
    return {
        'country': country.get('iso_code'),
        'country_name': country.get('names', {}).get('en'),
        'city': record.get('city', {}).get('names', {}).get('en'),
    }


def _asn_fields(record: dict) -> dict:
    return {
        'asn': record.get('autonomous_system_number'),
        'org': record.get('autonomous_system_organization'),
    }


def _public_address(ip: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return None
    address = getattr(address, 'ipv4_mapped', None) or address
    # is_global alone lets multicast through.
    if not address.is_global or address.is_multicast or address.is_reserved:
        return None
    return address


class GeoIPService:
    """The two databases on disk and their readers. Knows nothing of the DB: outcomes
    of the last refresh stay on the object for refresh_from_settings to record."""

    def __init__(self, directory: Path = Path('/app/geoip')):
        self.directory = directory
        self.last_error: str | None = None
        self.last_installed = False
        self._readers: dict[str, Reader] = {}
        self._lock = asyncio.Lock()

    @property
    def complete(self) -> bool:
        return all(edition in self._readers for edition in EDITIONS)

    def build_epoch(self, edition: str) -> int | None:
        reader = self._readers.get(edition)
        return reader.metadata().build_epoch if reader else None

    def _mmdb_path(self, edition: str) -> Path:
        return self.directory / f'{edition}.mmdb'

    def _sidecar_path(self, edition: str) -> Path:
        return self.directory / f'{edition}.mmdb.last-modified'

    def _tmp_mmdb_path(self, edition: str) -> Path:
        return self.directory / f'{edition}.mmdb.tmp'

    def _tmp_archive_path(self, edition: str) -> Path:
        return self.directory / f'{edition}.tar.gz.tmp'

    def _record(self, edition: str, address, extract: Callable[[dict], dict]) -> dict:
        reader = self._readers.get(edition)
        if reader is None:
            return {}
        try:
            record = reader.get(address)
            if not record:
                return {}
            return GeoInfo(**extract(record)).model_dump(exclude_none=True)
        except Exception as e:
            logger.debug(f'GeoIP {edition} lookup failed: {type(e).__name__}')
            return {}

    def lookup(self, ip: str) -> GeoInfo | None:
        address = _public_address(ip)
        if address is None:
            return None
        fields = {**self._record(CITY_EDITION, address, _city_fields),
                  **self._record(ASN_EDITION, address, _asn_fields)}
        return GeoInfo(**fields) if fields else None

    def countries(self, ips: Iterable[str]) -> list[str]:
        codes = (info.country for info in map(self.lookup, ips) if info)
        return list(dict.fromkeys(code for code in codes if code))

    def _open_existing(self, edition: str) -> Reader | None:
        try:
            return _open_checked(self._mmdb_path(edition), edition)
        except FileNotFoundError:
            return None
        except Exception as e:
            logger.error(f'GeoIP {edition} database on disk is unusable: {type(e).__name__}')
            return None

    def load(self) -> bool:
        """Open what is on disk; True when at least one database is usable."""
        for edition in EDITIONS:
            if edition not in self._readers:
                reader = self._open_existing(edition)
                if reader:
                    self._readers[edition] = reader
        return bool(self._readers)

    async def _is_current(self, edition: str, last_modified: str | None) -> bool:
        if not last_modified:
            return False
        if edition not in self._readers:
            reader = await asyncio.to_thread(self._open_existing, edition)
            if reader is None:
                return False
            self._readers[edition] = reader
        if not self._mmdb_path(edition).exists():
            return False
        try:
            return self._sidecar_path(edition).read_text() == last_modified
        except OSError:
            return False

    def _store_last_modified(self, edition: str, last_modified: str | None) -> None:
        # A failure here costs one extra download next time, never a wrong skip: the
        # stale value can't match the header that just made us download.
        try:
            if last_modified:
                self._sidecar_path(edition).write_text(last_modified)
            else:
                self._sidecar_path(edition).unlink(missing_ok=True)
        except OSError as e:
            logger.warning(f'Could not update the GeoIP {edition} sidecar: {type(e).__name__}')

    async def _refresh_edition(self, client: httpx.AsyncClient, edition: str) -> None:
        url = DOWNLOAD_URL.format(edition=edition)
        # Status first: bad credentials must surface even when the sidecar still matches.
        head = await client.head(url)
        if not head.is_success:
            raise _RefreshFailure(_describe_status(head.status_code))
        last_modified = head.headers.get('last-modified')
        if await self._is_current(edition, last_modified):
            return

        self.directory.mkdir(parents=True, exist_ok=True)
        archive = self._tmp_archive_path(edition)
        tmp = self._tmp_mmdb_path(edition)
        try:
            await _download(client, url, archive)
            reader = await asyncio.to_thread(_unpack_and_open, archive, tmp, edition)
            try:
                os.replace(tmp, self._mmdb_path(edition))
            except OSError:
                reader.close()
                raise
        finally:
            archive.unlink(missing_ok=True)
            tmp.unlink(missing_ok=True)

        previous = self._readers.get(edition)
        self._readers[edition] = reader
        # Safe straight after the swap: lookup only runs on this event loop.
        if previous:
            previous.close()
        self.last_installed = True
        self._store_last_modified(edition, last_modified)
        logger.info(f'Installed GeoIP database {edition}')

    async def _refresh_locked(self, account_id: str, license_key: str, *,
                              transport: httpx.AsyncBaseTransport | None = None) -> None:
        self.last_error = None
        self.last_installed = False
        errors = []
        # httpx strips the basic auth header when the redirect leaves MaxMind's origin.
        async with httpx.AsyncClient(auth=(account_id, license_key), transport=transport,
                                     follow_redirects=True, timeout=HTTP_TIMEOUT) as client:
            for edition in EDITIONS:
                try:
                    async with asyncio.timeout(EDITION_TIMEOUT_SECONDS):
                        await self._refresh_edition(client, edition)
                except _RefreshFailure as e:
                    message = str(e)
                except httpx.HTTPError as e:
                    message = f'Network error ({type(e).__name__})'
                except TimeoutError:
                    message = f'Timed out after {EDITION_TIMEOUT_SECONDS} s'
                except Exception as e:
                    message = f'Unexpected error ({type(e).__name__})'
                else:
                    continue
                errors.append(f'{edition}: {message}')
                logger.warning(f'GeoIP refresh failed for {edition}: {message}')
        self.last_error = '; '.join(errors) or None

    async def refresh(self, account_id: str, license_key: str, *,
                      transport: httpx.AsyncBaseTransport | None = None) -> None:
        async with self._lock:
            await self._refresh_locked(account_id, license_key, transport=transport)

    async def clear(self) -> None:
        async with self._lock:
            readers, self._readers = self._readers, {}
            for reader in readers.values():
                reader.close()
            self.last_error = None
            self.last_installed = False
            for edition in EDITIONS:
                for path in (self._mmdb_path(edition), self._sidecar_path(edition),
                             self._tmp_mmdb_path(edition), self._tmp_archive_path(edition)):
                    try:
                        path.unlink(missing_ok=True)
                    except OSError as e:
                        logger.error(f'Could not delete {path.name}: {type(e).__name__}')


_service: GeoIPService | None = None


def get_geoip() -> GeoIPService:
    global _service
    if _service is None:
        _service = GeoIPService()
    return _service


async def _record_outcome(service: GeoIPService, credentials: tuple[str, str]) -> None:
    async with async_session_maker() as db:
        row = await db.get(GeoipSettings, GEOIP_ROW_ID)
        # Credentials cleared or replaced during the download: this outcome no longer
        # describes them, and writing it would bring back status the route just reset.
        if row is None or (row.account_id, row.license_key) != credentials:
            return
        now = utcnow()
        row.last_checked_at = now
        if service.last_installed:
            row.last_updated_at = now
        row.city_build = service.build_epoch(CITY_EDITION)
        row.asn_build = service.build_epoch(ASN_EDITION)
        row.last_status = 'error' if service.last_error else 'ok'
        row.last_error = service.last_error[:LAST_ERROR_MAX_LENGTH] if service.last_error else None
        await db.commit()


async def refresh_from_settings(*, service: GeoIPService | None = None,
                                transport: httpx.AsyncBaseTransport | None = None) -> None:
    service = service or get_geoip()
    # The lock spans reading the credentials, so a clear either runs first (and this
    # sees none) or waits and deletes whatever this installs.
    async with service._lock:
        async with async_session_maker() as db:
            row = await db.get(GeoipSettings, GEOIP_ROW_ID)
            credentials = (row.account_id, row.license_key) if row else (None, None)
        if not all(credentials):
            return
        await service._refresh_locked(*credentials, transport=transport)
        await _record_outcome(service, credentials)


async def startup_refresh_needed(service: GeoIPService) -> bool:
    async with async_session_maker() as db:
        row = await db.get(GeoipSettings, GEOIP_ROW_ID)
    if row is None or not (row.account_id and row.license_key):
        return False
    if not service.complete or row.last_checked_at is None:
        return True
    return utcnow() - row.last_checked_at > timedelta(hours=REFRESH_INTERVAL_HOURS)


_background_refreshes: set[asyncio.Task] = set()


async def _logged_refresh() -> None:
    try:
        await refresh_from_settings()
    except Exception as e:
        logger.error(f'GeoIP refresh failed: {type(e).__name__}')


def start_refresh() -> asyncio.Task:
    task = asyncio.create_task(_logged_refresh())
    _background_refreshes.add(task)
    task.add_done_callback(_background_refreshes.discard)
    return task


async def cancel_background_refreshes() -> None:
    tasks = tuple(_background_refreshes)
    for task in tasks:
        task.cancel()
    await asyncio.gather(*tasks, return_exceptions=True)
