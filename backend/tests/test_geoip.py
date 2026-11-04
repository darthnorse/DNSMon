import asyncio
import io
import logging
import shutil
import tarfile
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import httpx
import maxminddb
import pytest

from backend import geoip as geoip_module
from backend.geoip import (
    ASN_EDITION,
    CITY_EDITION,
    EDITIONS,
    GeoIPService,
    get_geoip,
    refresh_from_settings,
)
from backend.models import GeoipSettings
from backend.schemas import GeoInfo
from backend.service import DNSMonService

DATA = Path(__file__).parent / "data"
FIXTURES = {CITY_EDITION: DATA / "GeoIP2-City-Test.mmdb", ASN_EDITION: DATA / "GeoLite2-ASN-Test.mmdb"}

ACCOUNT = "271828"
KEY = "abcSECRETkey123"
SIGNATURE = "SIGsecret987"
LAST_MODIFIED = "Tue, 03 Nov 2026 10:00:00 GMT"
NEWER = "Fri, 06 Nov 2026 10:00:00 GMT"
IN_BOTH = "89.160.20.130"
EXPECTED = GeoInfo(country="SE", country_name="Sweden", city="Linköping",
                   asn=29518, org="Bredband2 AB")


def _regular(tar, name, content=b"licence text"):
    info = tarfile.TarInfo(name)
    info.size = len(content)
    tar.addfile(info, io.BytesIO(content))


def _tarball(edition, source=None, *, build=None):
    """Same shape as a real MaxMind archive: a directory, licence files and one mmdb."""
    folder = f"{edition}_20261103"
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
        directory = tarfile.TarInfo(folder)
        directory.type = tarfile.DIRTYPE
        tar.addfile(directory)
        _regular(tar, f"{folder}/COPYRIGHT.txt")
        _regular(tar, f"{folder}/LICENSE.txt")
        _regular(tar, f"{folder}/{edition}.mmdb", (source or FIXTURES[edition]).read_bytes())
        if build:
            build(tar)
    return buffer.getvalue()


class FakeMaxMind:
    """Answers like download.maxmind.com: HEAD and GET per edition, optionally through
    a redirect to a presigned storage URL."""

    def __init__(self, *, redirect=False):
        self.redirect = redirect
        self.last_modified = LAST_MODIFIED
        self.archives = {edition: _tarball(edition) for edition in EDITIONS}
        self.status = {}
        self.raises = {}
        self.download_headers = {}
        self.requests = []
        self.gate = None

    def transport(self):
        return httpx.MockTransport(self._handle)

    def gets(self):
        return [r for r in self.requests if r.method == "GET" and r.url.host == "download.maxmind.com"]

    async def _handle(self, request):
        self.requests.append(request)
        edition = next(e for e in EDITIONS if e in request.url.path)
        if edition in self.raises:
            raise self.raises[edition]
        if edition in self.status:
            return httpx.Response(self.status[edition], request=request)
        if self.redirect and request.url.host == "download.maxmind.com":
            return httpx.Response(302, headers={
                "Location": f"https://storage.example.com/{edition}?X-Amz-Signature={SIGNATURE}"})
        headers = {"Last-Modified": self.last_modified} if self.last_modified else {}
        if request.method == "HEAD":
            return httpx.Response(200, headers=headers)
        if self.gate:
            await self.gate.wait()
        # stream=, not content=: httpx reads content= eagerly, leaving nothing for aiter_raw.
        return httpx.Response(200, headers={**headers, **self.download_headers},
                              stream=httpx.ByteStream(self.archives[edition]))


async def _installed(tmp_path, maxmind=None):
    service = GeoIPService(tmp_path)
    await service.refresh(ACCOUNT, KEY, transport=(maxmind or FakeMaxMind()).transport())
    assert service.last_error is None
    return service


def _assert_clean(text):
    for secret in (KEY, ACCOUNT, SIGNATURE, "http://", "https://"):
        assert secret not in text


def _temp_files(directory):
    return [p.name for p in directory.iterdir() if p.name.endswith(".tmp")]


async def test_refresh_installs_and_lookup_works(tmp_path):
    maxmind = FakeMaxMind()

    service = await _installed(tmp_path, maxmind)

    assert service.lookup(IN_BOTH) == EXPECTED
    assert service.last_installed is True
    assert (tmp_path / f"{CITY_EDITION}.mmdb").exists()
    assert (tmp_path / f"{ASN_EDITION}.mmdb").exists()
    assert _temp_files(tmp_path) == []
    assert service.build_epoch(CITY_EDITION) == 1792695177
    assert service.build_epoch(ASN_EDITION) == 1792695177
    assert maxmind.requests[0].url == (
        f"https://download.maxmind.com/geoip/databases/{CITY_EDITION}/download?suffix=tar.gz")


async def test_refresh_ignores_other_members_of_the_archive(tmp_path):
    service = await _installed(tmp_path)

    assert sorted(p.name for p in tmp_path.iterdir() if not p.name.endswith(".last-modified")) == [
        f"{ASN_EDITION}.mmdb", f"{CITY_EDITION}.mmdb"]
    assert service.lookup(IN_BOTH) is not None


def _with_extra_member(maker):
    return lambda maxmind: maxmind.archives.update(
        {CITY_EDITION: _tarball(CITY_EDITION, build=maker)})


def _second_mmdb(tar):
    _regular(tar, "other/second.mmdb", FIXTURES[CITY_EDITION].read_bytes())


def _traversal(tar):
    _regular(tar, "../../evil.txt")


def _absolute(tar):
    _regular(tar, "/etc/evil.txt")


def _no_mmdb_archive():
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
        _regular(tar, "LICENSE.txt")
    return buffer.getvalue()


def _link_mmdb_archive(link_type):
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
        info = tarfile.TarInfo("dir/GeoLite2-City.mmdb")
        info.type = link_type
        info.linkname = "/etc/passwd"
        tar.addfile(info)
    return buffer.getvalue()


FAILURES = {
    "401": lambda m: m.status.update({CITY_EDITION: 401}),
    "429": lambda m: m.status.update({CITY_EDITION: 429}),
    "500": lambda m: m.status.update({CITY_EDITION: 500}),
    "network": lambda m: m.raises.update(
        {CITY_EDITION: httpx.ConnectTimeout(f"failed for https://{ACCOUNT}:{KEY}@x/?sig={SIGNATURE}")}),
    "corrupt_tar": lambda m: m.archives.update({CITY_EDITION: b"this is not a tarball"}),
    "truncated_tar": lambda m: m.archives.update({CITY_EDITION: m.archives[CITY_EDITION][:4000]}),
    "traversal_member": _with_extra_member(_traversal),
    "absolute_member": _with_extra_member(_absolute),
    "two_mmdbs": _with_extra_member(_second_mmdb),
    "no_mmdb": lambda m: m.archives.update({CITY_EDITION: _no_mmdb_archive()}),
    "symlink_mmdb": lambda m: m.archives.update({CITY_EDITION: _link_mmdb_archive(tarfile.SYMTYPE)}),
    "hardlink_mmdb": lambda m: m.archives.update({CITY_EDITION: _link_mmdb_archive(tarfile.LNKTYPE)}),
    "device_mmdb": lambda m: m.archives.update({CITY_EDITION: _link_mmdb_archive(tarfile.CHRTYPE)}),
    "not_a_database": lambda m: m.archives.update(
        {CITY_EDITION: _tarball(CITY_EDITION, source=Path(__file__))}),
    "swapped_edition": lambda m: m.archives.update(
        {CITY_EDITION: _tarball(CITY_EDITION, source=FIXTURES[ASN_EDITION])}),
}


@pytest.mark.parametrize("failure", FAILURES)
async def test_failed_refresh_keeps_previous_db(tmp_path, failure, caplog):
    service = await _installed(tmp_path)
    before = (tmp_path / f"{CITY_EDITION}.mmdb").read_bytes()
    maxmind = FakeMaxMind()
    maxmind.last_modified = NEWER
    FAILURES[failure](maxmind)

    with caplog.at_level(logging.DEBUG, logger="backend.geoip"):
        await service.refresh(ACCOUNT, KEY, transport=maxmind.transport())

    assert service.lookup(IN_BOTH) == EXPECTED
    assert (tmp_path / f"{CITY_EDITION}.mmdb").read_bytes() == before
    assert (tmp_path / f"{CITY_EDITION}.mmdb.last-modified").read_text() == LAST_MODIFIED
    assert service.last_error.startswith(CITY_EDITION)
    _assert_clean(service.last_error)
    assert "GeoIP refresh failed" in caplog.text
    _assert_clean(caplog.text)
    assert _temp_files(tmp_path) == []


@pytest.mark.parametrize("failure, message", [
    ("401", "MaxMind rejected the credentials (HTTP 401)"),
    ("429", "MaxMind rate limit reached (HTTP 429)"),
    ("500", "HTTP 500"),
    ("network", "Network error (ConnectTimeout)"),
    ("traversal_member", "Archive invalid"),
    ("swapped_edition", "Archive invalid"),
])
async def test_error_says_what_went_wrong(tmp_path, failure, message):
    service = await _installed(tmp_path)
    maxmind = FakeMaxMind()
    maxmind.last_modified = NEWER
    FAILURES[failure](maxmind)

    await service.refresh(ACCOUNT, KEY, transport=maxmind.transport())

    assert message in service.last_error


async def test_unchanged_last_modified_skips_download(tmp_path):
    service = await _installed(tmp_path)
    maxmind = FakeMaxMind()

    await service.refresh(ACCOUNT, KEY, transport=maxmind.transport())

    assert [r.method for r in maxmind.requests] == ["HEAD", "HEAD"]
    assert service.last_error is None
    assert service.last_installed is False


async def test_new_last_modified_downloads_and_updates_sidecar(tmp_path):
    service = await _installed(tmp_path)
    maxmind = FakeMaxMind()
    maxmind.last_modified = NEWER

    await service.refresh(ACCOUNT, KEY, transport=maxmind.transport())

    assert len(maxmind.gets()) == 2
    assert service.last_installed is True
    assert (tmp_path / f"{ASN_EDITION}.mmdb.last-modified").read_text() == NEWER


async def test_restart_with_files_and_sidecars_does_not_download(tmp_path):
    await _installed(tmp_path)
    restarted = GeoIPService(tmp_path)
    assert restarted.load() is True
    maxmind = FakeMaxMind()

    await restarted.refresh(ACCOUNT, KEY, transport=maxmind.transport())

    assert maxmind.gets() == []
    assert restarted.lookup(IN_BOTH) == EXPECTED


async def test_sidecar_is_ignored_when_mmdb_is_missing(tmp_path):
    service = await _installed(tmp_path)
    (tmp_path / f"{CITY_EDITION}.mmdb").unlink()
    maxmind = FakeMaxMind()

    await service.refresh(ACCOUNT, KEY, transport=maxmind.transport())

    assert [r.url.path for r in maxmind.gets()] == [
        f"/geoip/databases/{CITY_EDITION}/download"]
    assert (tmp_path / f"{CITY_EDITION}.mmdb").exists()


async def test_no_last_modified_header_downloads_and_drops_stale_sidecar(tmp_path):
    service = await _installed(tmp_path)
    maxmind = FakeMaxMind()
    maxmind.last_modified = None

    await service.refresh(ACCOUNT, KEY, transport=maxmind.transport())

    assert len(maxmind.gets()) == 2
    assert not (tmp_path / f"{CITY_EDITION}.mmdb.last-modified").exists()


async def test_rejected_credentials_surface_even_when_sidecar_matches(tmp_path):
    service = await _installed(tmp_path)
    maxmind = FakeMaxMind()
    maxmind.status = {CITY_EDITION: 401, ASN_EDITION: 401}

    await service.refresh(ACCOUNT, "wrongKEY", transport=maxmind.transport())

    assert "MaxMind rejected the credentials (HTTP 401)" in service.last_error
    assert service.lookup(IN_BOTH) == EXPECTED


async def test_redirect_is_followed_without_leaking_credentials_or_signature(tmp_path):
    maxmind = FakeMaxMind(redirect=True)

    service = await _installed(tmp_path, maxmind)

    assert service.lookup(IN_BOTH) == EXPECTED
    storage = [r for r in maxmind.requests if r.url.host == "storage.example.com"]
    origin = [r for r in maxmind.requests if r.url.host == "download.maxmind.com"]
    assert {r.method for r in storage} == {"HEAD", "GET"}
    assert all("authorization" in r.headers for r in origin)
    assert not any("authorization" in r.headers for r in storage)


async def test_storage_failure_after_redirect_does_not_leak_signature(tmp_path, caplog):
    service = GeoIPService(tmp_path)
    maxmind = FakeMaxMind(redirect=True)

    async def expired(request):
        if request.url.host == "storage.example.com":
            return httpx.Response(403, text=f"expired {request.url}")
        return await maxmind._handle(request)

    with caplog.at_level(logging.DEBUG, logger="backend.geoip"):
        await service.refresh(ACCOUNT, KEY, transport=httpx.MockTransport(expired))

    assert "HTTP 403" in service.last_error
    _assert_clean(service.last_error)
    _assert_clean(caplog.text)


async def test_asn_failure_does_not_undo_city_install(tmp_path):
    service = GeoIPService(tmp_path)
    maxmind = FakeMaxMind()
    maxmind.status = {ASN_EDITION: 500}

    await service.refresh(ACCOUNT, KEY, transport=maxmind.transport())

    assert service.last_error == f"{ASN_EDITION}: HTTP 500"
    assert service.last_installed is True
    assert (tmp_path / f"{CITY_EDITION}.mmdb").exists()
    assert not (tmp_path / f"{ASN_EDITION}.mmdb").exists()
    assert service.lookup(IN_BOTH) == GeoInfo(country="SE", country_name="Sweden", city="Linköping")


async def test_city_failure_does_not_undo_asn_install(tmp_path):
    service = GeoIPService(tmp_path)
    maxmind = FakeMaxMind()
    maxmind.status = {CITY_EDITION: 500}

    await service.refresh(ACCOUNT, KEY, transport=maxmind.transport())

    assert service.last_error == f"{CITY_EDITION}: HTTP 500"
    assert service.lookup(IN_BOTH) == GeoInfo(asn=29518, org="Bredband2 AB")


async def test_both_editions_failing_names_both(tmp_path):
    service = GeoIPService(tmp_path)
    maxmind = FakeMaxMind()
    maxmind.status = {CITY_EDITION: 500, ASN_EDITION: 429}

    await service.refresh(ACCOUNT, KEY, transport=maxmind.transport())

    assert CITY_EDITION in service.last_error and ASN_EDITION in service.last_error


async def test_tarball_served_with_gzip_content_encoding_is_not_decoded(tmp_path):
    maxmind = FakeMaxMind()
    maxmind.download_headers = {"Content-Encoding": "gzip"}

    service = await _installed(tmp_path, maxmind)

    assert service.lookup(IN_BOTH) == EXPECTED
    assert {r.headers["accept-encoding"] for r in maxmind.gets()} == {"identity"}


async def test_oversized_download_is_refused(tmp_path, monkeypatch):
    monkeypatch.setattr(geoip_module, "MAX_DOWNLOAD_BYTES", 1000)
    service = GeoIPService(tmp_path)

    await service.refresh(ACCOUNT, KEY, transport=FakeMaxMind().transport())

    assert "Download larger than" in service.last_error
    assert list(tmp_path.iterdir()) == []


async def test_oversized_member_is_refused(tmp_path, monkeypatch):
    monkeypatch.setattr(geoip_module, "MAX_MMDB_BYTES", 1000)
    service = GeoIPService(tmp_path)

    await service.refresh(ACCOUNT, KEY, transport=FakeMaxMind().transport())

    assert "Archive invalid: database larger than" in service.last_error
    assert list(tmp_path.iterdir()) == []


async def test_too_many_members_is_refused(tmp_path, monkeypatch):
    monkeypatch.setattr(geoip_module, "MAX_ARCHIVE_MEMBERS", 2)
    service = GeoIPService(tmp_path)

    await service.refresh(ACCOUNT, KEY, transport=FakeMaxMind().transport())

    assert "Archive invalid: too many members" in service.last_error


async def test_stalled_download_times_out_and_cleans_up(tmp_path, monkeypatch):
    monkeypatch.setattr(geoip_module, "EDITION_TIMEOUT_SECONDS", 0.05)
    service = GeoIPService(tmp_path)
    maxmind = FakeMaxMind()
    maxmind.gate = asyncio.Event()

    await service.refresh(ACCOUNT, KEY, transport=maxmind.transport())

    assert "Timed out" in service.last_error
    assert list(tmp_path.iterdir()) == []


async def test_unwritable_directory_is_reported_not_raised(tmp_path):
    blocker = tmp_path / "file"
    blocker.write_text("x")
    service = GeoIPService(blocker / "geoip")

    await service.refresh(ACCOUNT, KEY, transport=FakeMaxMind().transport())

    assert "Unexpected error (NotADirectoryError)" in service.last_error


async def test_concurrent_refreshes_download_once(tmp_path):
    service = GeoIPService(tmp_path)
    maxmind = FakeMaxMind()
    transport = maxmind.transport()

    await asyncio.gather(service.refresh(ACCOUNT, KEY, transport=transport),
                         service.refresh(ACCOUNT, KEY, transport=transport))

    assert len(maxmind.gets()) == 2
    assert service.lookup(IN_BOTH) == EXPECTED


async def test_extraction_runs_off_the_event_loop(tmp_path, monkeypatch):
    original = geoip_module._unpack_and_open
    threads = []

    def spy(*args):
        threads.append(threading.current_thread())
        return original(*args)

    monkeypatch.setattr(geoip_module, "_unpack_and_open", spy)

    await _installed(tmp_path)

    assert len(threads) == 2
    assert threading.main_thread() not in threads


def test_lookup_without_db_returns_none(tmp_path):
    assert GeoIPService(tmp_path).lookup(IN_BOTH) is None


@pytest.mark.parametrize("ip", [
    "10.0.0.1", "192.168.1.1", "172.16.0.1", "127.0.0.1", "::1", "169.254.1.1", "fe80::1",
    "fd00::1", "224.0.0.1", "ff02::1", "240.0.0.1", "0.0.0.0", "::", "100.64.0.1",
    "::ffff:10.0.0.1", "not-an-ip", "", "999.1.1.1",
])
async def test_private_ip_returns_none(tmp_path, ip):
    service = await _installed(tmp_path)

    assert service.lookup(ip) is None


async def test_lookup_of_address_in_neither_db_returns_none(tmp_path):
    service = await _installed(tmp_path)

    assert service.lookup("8.8.8.8") is None


async def test_lookup_of_ipv4_mapped_address_matches_ipv4(tmp_path):
    service = await _installed(tmp_path)

    assert service.lookup(f"::ffff:{IN_BOTH}") == EXPECTED


async def test_lookup_ipv6(tmp_path):
    service = await _installed(tmp_path)

    assert service.lookup("2001:218::1").country == "JP"


class _StubReader:
    def __init__(self, record=None, error=None):
        self.record, self.error = record, error

    def get(self, ip):
        if self.error:
            raise self.error
        return self.record

    def close(self):
        pass


def _stubbed(tmp_path, city=None, asn=None):
    service = GeoIPService(tmp_path)
    service._readers = {CITY_EDITION: _StubReader(city), ASN_EDITION: _StubReader(asn)}
    return service


def test_country_falls_back_to_registered_country(tmp_path):
    service = _stubbed(tmp_path, city={
        "registered_country": {"iso_code": "DE", "names": {"en": "Germany"}}})

    assert service.lookup(IN_BOTH) == GeoInfo(country="DE", country_name="Germany")


def test_country_is_preferred_over_registered_country(tmp_path):
    service = _stubbed(tmp_path, city={
        "country": {"iso_code": "SE"}, "registered_country": {"iso_code": "DE"}})

    assert service.lookup(IN_BOTH).country == "SE"


@pytest.mark.parametrize("city", [
    {"country": "SE"},
    {"country": {"iso_code": 5}},
    {"country": {"iso_code": "SE", "names": "Sweden"}},
    {"city": ["London"]},
    "not a mapping",
    [],
])
def test_malformed_record_does_not_raise(tmp_path, city):
    assert _stubbed(tmp_path, city=city).lookup(IN_BOTH) is None


def test_malformed_city_record_keeps_good_asn(tmp_path):
    service = _stubbed(tmp_path, city={"country": "SE"}, asn={
        "autonomous_system_number": 1, "autonomous_system_organization": "Org"})

    assert service.lookup(IN_BOTH) == GeoInfo(asn=1, org="Org")


def test_record_without_any_geo_fields_returns_none(tmp_path):
    assert _stubbed(tmp_path, city={"location": {"latitude": 1.0}}).lookup(IN_BOTH) is None


@pytest.mark.parametrize("error", [
    maxminddb.InvalidDatabaseError("bad"), ValueError("bad"), OSError("bad")])
def test_reader_error_does_not_raise(tmp_path, error):
    service = GeoIPService(tmp_path)
    service._readers = {CITY_EDITION: _StubReader(error=error)}

    assert service.lookup(IN_BOTH) is None


async def test_countries_are_distinct_and_keep_order(tmp_path):
    service = await _installed(tmp_path)

    assert service.countries(["81.2.69.160", "10.0.0.1", IN_BOTH, "81.2.69.161", "8.8.8.8"]) == ["GB", "SE"]


def test_load_without_files_returns_false_quietly(tmp_path, caplog):
    assert GeoIPService(tmp_path / "absent").load() is False
    assert caplog.text == ""


def test_load_corrupt_file_returns_false(tmp_path, caplog):
    (tmp_path / f"{CITY_EDITION}.mmdb").write_bytes(b"corrupt")

    service = GeoIPService(tmp_path)

    assert service.load() is False
    assert CITY_EDITION in caplog.text
    assert service.lookup(IN_BOTH) is None


def test_load_refuses_a_file_of_the_wrong_type(tmp_path):
    shutil.copy(FIXTURES[ASN_EDITION], tmp_path / f"{CITY_EDITION}.mmdb")

    assert GeoIPService(tmp_path).load() is False


def test_load_keeps_the_good_database_beside_a_corrupt_one(tmp_path):
    shutil.copy(FIXTURES[ASN_EDITION], tmp_path / f"{ASN_EDITION}.mmdb")
    (tmp_path / f"{CITY_EDITION}.mmdb").write_bytes(b"corrupt")

    service = GeoIPService(tmp_path)

    assert service.load() is True
    assert service.complete is False
    assert service.lookup(IN_BOTH).asn == 29518


def test_load_survives_an_unsearchable_directory(tmp_path, caplog):
    locked = tmp_path / "locked"
    locked.mkdir(mode=0o000)
    try:
        assert GeoIPService(locked).load() is False
    finally:
        locked.chmod(0o700)

    assert "PermissionError" in caplog.text


async def test_corrupt_file_with_matching_sidecar_is_replaced_at_refresh(tmp_path):
    await _installed(tmp_path)
    (tmp_path / f"{CITY_EDITION}.mmdb").write_bytes(b"corrupt")
    restarted = GeoIPService(tmp_path)
    restarted.load()
    maxmind = FakeMaxMind()

    await restarted.refresh(ACCOUNT, KEY, transport=maxmind.transport())

    assert [r.url.path for r in maxmind.gets()] == [f"/geoip/databases/{CITY_EDITION}/download"]
    assert restarted.lookup(IN_BOTH) == EXPECTED


async def test_clear_unloads_and_deletes_everything(tmp_path):
    service = await _installed(tmp_path)

    await service.clear()

    assert service.lookup(IN_BOTH) is None
    assert service.complete is False
    assert list(tmp_path.iterdir()) == []


async def test_clear_survives_a_file_it_cannot_delete(tmp_path, monkeypatch, caplog):
    service = await _installed(tmp_path)

    def refuse(self, missing_ok=False):
        raise PermissionError("nope")

    monkeypatch.setattr(Path, "unlink", refuse)

    await service.clear()

    assert service.lookup(IN_BOTH) is None
    assert "Could not delete" in caplog.text


async def test_clear_waits_for_a_running_refresh_and_wins(tmp_path):
    service = GeoIPService(tmp_path)
    maxmind = FakeMaxMind()
    maxmind.gate = asyncio.Event()

    refresh = asyncio.create_task(service.refresh(ACCOUNT, KEY, transport=maxmind.transport()))
    while not maxmind.requests or maxmind.requests[-1].method != "GET":
        await asyncio.sleep(0)
    clear = asyncio.create_task(service.clear())
    await asyncio.sleep(0)
    maxmind.gate.set()
    await asyncio.gather(refresh, clear)

    assert service.lookup(IN_BOTH) is None
    assert list(tmp_path.iterdir()) == []


def test_singleton_is_shared():
    assert get_geoip() is get_geoip()


async def _seed(db_session, **fields):
    db_session.add(GeoipSettings(id=1, **fields))
    await db_session.commit()


async def _stored(db_session):
    db_session.expire_all()
    return await db_session.get(GeoipSettings, 1)


async def test_job_records_success(db_session, tmp_path):
    await _seed(db_session, account_id=ACCOUNT, license_key=KEY,
                last_status="error", last_error="old failure")
    service = GeoIPService(tmp_path)

    await refresh_from_settings(service=service, transport=FakeMaxMind().transport())

    row = await _stored(db_session)
    assert row.last_status == "ok"
    assert row.last_error is None
    assert row.last_checked_at is not None
    assert row.last_updated_at is not None
    assert row.city_build == row.asn_build == 1792695177


async def test_job_updates_only_checked_at_when_nothing_changed(db_session, tmp_path):
    long_ago = datetime.now(timezone.utc) - timedelta(days=3)
    await _seed(db_session, account_id=ACCOUNT, license_key=KEY,
                last_checked_at=long_ago, last_updated_at=long_ago)
    service = await _installed(tmp_path)

    await refresh_from_settings(service=service, transport=FakeMaxMind().transport())

    row = await _stored(db_session)
    assert row.last_checked_at > long_ago
    assert row.last_updated_at == long_ago
    assert row.last_status == "ok"


async def test_job_records_scrubbed_error(db_session, tmp_path):
    await _seed(db_session, account_id=ACCOUNT, license_key=KEY)
    service = await _installed(tmp_path)
    maxmind = FakeMaxMind()
    maxmind.status = {ASN_EDITION: 401}

    await refresh_from_settings(service=service, transport=maxmind.transport())

    row = await _stored(db_session)
    assert row.last_status == "error"
    assert row.last_error == f"{ASN_EDITION}: MaxMind rejected the credentials (HTTP 401)"
    assert row.last_updated_at is None
    assert row.city_build == 1792695177
    assert row.asn_build == 1792695177


async def test_job_truncates_error_to_column(db_session, tmp_path, monkeypatch):
    await _seed(db_session, account_id=ACCOUNT, license_key=KEY)
    service = GeoIPService(tmp_path)

    async def fail(*args, **kwargs):
        service.last_error = "x" * 500
        service.last_installed = False

    monkeypatch.setattr(service, "_refresh_locked", fail)

    await refresh_from_settings(service=service)

    assert (await _stored(db_session)).last_error == "x" * 200


async def test_job_without_credentials_is_a_quiet_noop(db_session, tmp_path, caplog):
    maxmind = FakeMaxMind()

    with caplog.at_level(logging.INFO, logger="backend.geoip"):
        await refresh_from_settings(service=GeoIPService(tmp_path), transport=maxmind.transport())

    assert maxmind.requests == []
    assert await _stored(db_session) is None
    assert caplog.text == ""


async def test_job_with_only_account_id_is_a_noop(db_session, tmp_path):
    await _seed(db_session, account_id=ACCOUNT)
    maxmind = FakeMaxMind()

    await refresh_from_settings(service=GeoIPService(tmp_path), transport=maxmind.transport())

    assert maxmind.requests == []


async def test_clear_during_job_leaves_no_files_and_no_status(db_session, tmp_path):
    await _seed(db_session, account_id=ACCOUNT, license_key=KEY)
    service = GeoIPService(tmp_path)
    maxmind = FakeMaxMind()
    maxmind.gate = asyncio.Event()

    job = asyncio.create_task(refresh_from_settings(service=service, transport=maxmind.transport()))
    while not maxmind.requests or maxmind.requests[-1].method != "GET":
        await asyncio.sleep(0)
    row = await _stored(db_session)
    row.account_id = None
    row.license_key = None
    await db_session.commit()
    clear = asyncio.create_task(service.clear())
    await asyncio.sleep(0)
    maxmind.gate.set()
    await asyncio.gather(job, clear)

    row = await _stored(db_session)
    assert (row.last_status, row.last_checked_at, row.city_build) == (None, None, None)
    assert list(tmp_path.iterdir()) == []
    assert service.lookup(IN_BOTH) is None


async def test_job_started_after_clear_does_not_download(db_session, tmp_path):
    await _seed(db_session, account_id=None, license_key=None)
    service = GeoIPService(tmp_path)
    maxmind = FakeMaxMind()

    await asyncio.gather(service.clear(),
                         refresh_from_settings(service=service, transport=maxmind.transport()))

    assert maxmind.requests == []


async def test_job_does_not_record_status_for_replaced_credentials(db_session, tmp_path):
    await _seed(db_session, account_id=ACCOUNT, license_key=KEY)
    maxmind = FakeMaxMind()
    maxmind.gate = asyncio.Event()

    job = asyncio.create_task(refresh_from_settings(
        service=GeoIPService(tmp_path), transport=maxmind.transport()))
    while not maxmind.requests or maxmind.requests[-1].method != "GET":
        await asyncio.sleep(0)
    row = await _stored(db_session)
    row.license_key = "otherKEY"
    await db_session.commit()
    maxmind.gate.set()
    await job

    assert (await _stored(db_session)).last_status is None


def _bare_dnsmon_service():
    service = DNSMonService()
    service.scheduler = MagicMock()
    service.alert_engine = MagicMock(invalidate_cache=AsyncMock())
    return service


def test_scheduler_registers_daily_refresh():
    service = _bare_dnsmon_service()

    service.start_scheduler()

    job = next(c.kwargs for c in service.scheduler.add_job.call_args_list
               if c.kwargs["id"] == "geoip_refresh")
    assert job["trigger"].interval == timedelta(hours=24)
    assert job["max_instances"] == 1


async def test_daily_job_swallows_errors(monkeypatch, caplog):
    monkeypatch.setattr(geoip_module, "refresh_from_settings", AsyncMock(side_effect=RuntimeError("boom")))

    await _bare_dnsmon_service().geoip_refresh_task()

    assert "GeoIP" in caplog.text


def _install_fixtures(service, *editions):
    service.directory.mkdir(parents=True)
    for edition in editions:
        shutil.copy(FIXTURES[edition], service.directory / f"{edition}.mmdb")


@pytest.fixture
def refresh_job(monkeypatch):
    job = AsyncMock()
    monkeypatch.setattr(geoip_module, "refresh_from_settings", job)
    return job


def _hours_ago(hours):
    return datetime.now(timezone.utc) - timedelta(hours=hours)


async def test_startup_loads_files_and_skips_refresh_when_recently_checked(
        db_session, isolated_geoip, refresh_job):
    await _seed(db_session, account_id=ACCOUNT, license_key=KEY, last_checked_at=_hours_ago(1))
    _install_fixtures(isolated_geoip, *EDITIONS)
    service = _bare_dnsmon_service()

    await service._start_geoip()

    assert isolated_geoip.lookup(IN_BOTH) == EXPECTED
    assert service._geoip_startup_refresh is None
    refresh_job.assert_not_awaited()


async def test_startup_refreshes_in_background_when_a_file_is_missing(
        db_session, isolated_geoip, refresh_job):
    await _seed(db_session, account_id=ACCOUNT, license_key=KEY, last_checked_at=_hours_ago(1))
    _install_fixtures(isolated_geoip, CITY_EDITION)
    service = _bare_dnsmon_service()

    await service._start_geoip()
    await service._geoip_startup_refresh

    refresh_job.assert_awaited_once()
    assert isolated_geoip.lookup(IN_BOTH).country == "SE"


@pytest.mark.parametrize("last_checked_hours_ago", [None, 25])
async def test_startup_refreshes_a_stale_check_even_with_files_present(
        db_session, isolated_geoip, refresh_job, last_checked_hours_ago):
    checked = None if last_checked_hours_ago is None else _hours_ago(last_checked_hours_ago)
    await _seed(db_session, account_id=ACCOUNT, license_key=KEY, last_checked_at=checked)
    _install_fixtures(isolated_geoip, *EDITIONS)
    service = _bare_dnsmon_service()

    await service._start_geoip()
    await service._geoip_startup_refresh

    refresh_job.assert_awaited_once()


@pytest.mark.parametrize("fields", [
    {},
    {"account_id": ACCOUNT},
    {"account_id": None, "license_key": None, "last_checked_at": None},
])
async def test_startup_without_credentials_starts_no_refresh(
        db_session, isolated_geoip, refresh_job, fields):
    if fields:
        await _seed(db_session, **fields)
    service = _bare_dnsmon_service()

    await service._start_geoip()

    assert service._geoip_startup_refresh is None
    refresh_job.assert_not_awaited()


async def test_startup_survives_an_unsearchable_directory(db_session, isolated_geoip, refresh_job):
    isolated_geoip.directory.mkdir(mode=0o000)
    service = _bare_dnsmon_service()
    try:
        await service._start_geoip()
    finally:
        isolated_geoip.directory.chmod(0o700)

    assert service._geoip_startup_refresh is None


async def test_startup_logs_and_carries_on_after_any_geoip_error(isolated_geoip, monkeypatch, caplog):
    monkeypatch.setattr(isolated_geoip, "load", MagicMock(side_effect=RuntimeError("boom")))
    service = _bare_dnsmon_service()

    await service._start_geoip()

    assert "RuntimeError" in caplog.text
    assert service._geoip_startup_refresh is None


async def test_shutdown_cancels_running_refreshes(monkeypatch):
    started = asyncio.Event()

    async def hang():
        started.set()
        await asyncio.sleep(3600)

    monkeypatch.setattr(geoip_module, "refresh_from_settings", hang)
    service = _bare_dnsmon_service()
    service.ingestion_service = MagicMock(stop=AsyncMock())
    from_route = geoip_module.start_refresh()
    await started.wait()
    service._geoip_startup_refresh = asyncio.create_task(asyncio.sleep(3600))
    startup_task = service._geoip_startup_refresh

    await service.shutdown()

    assert from_route.cancelled()
    assert startup_task.cancelled()


async def test_background_refresh_logs_failures(monkeypatch, caplog):
    monkeypatch.setattr(geoip_module, "refresh_from_settings", AsyncMock(side_effect=RuntimeError("boom")))

    await geoip_module.start_refresh()

    assert "RuntimeError" in caplog.text
