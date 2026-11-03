from datetime import datetime, timedelta, timezone

from httpx import AsyncClient

from backend.models import DomainLabel, Query

T0 = datetime(2026, 11, 3, 14, 3, 27, tzinfo=timezone.utc)
LAPTOP = "192.168.1.62"
PHONE = "192.168.1.77"


async def _add(db_session, offset_s: float, domain: str, client_ip: str = LAPTOP, server: str = "pi") -> Query:
    q = Query(timestamp=T0 + timedelta(seconds=offset_s), domain=domain, client_ip=client_ip, server=server)
    db_session.add(q)
    await db_session.commit()
    await db_session.refresh(q)
    return q


def _domains(rows: list[dict]) -> list[str]:
    return [r["domain"] for r in rows]


async def test_anchor_by_id_returns_device_timeline_in_time_order(async_admin_client: AsyncClient, db_session):
    await _add(db_session, -400, "too-early.example")
    await _add(db_session, -120, "news.example")
    await _add(db_session, -8, "redirect.example")
    await _add(db_session, -5, "phone.example", client_ip=PHONE)
    hit = await _add(db_session, 0, "bad.example")
    await _add(db_session, 14, "payload.example")
    await _add(db_session, 400, "too-late.example")

    r = await async_admin_client.get("/api/queries/context", params={"query_id": hit.id, "window": 5})

    assert r.status_code == 200, r.text
    body = r.json()
    assert body["anchor"]["id"] == hit.id
    assert body["client_ip"] == LAPTOP
    assert _domains(body["before"]) == ["news.example", "redirect.example"]
    assert _domains(body["after"]) == ["payload.example"]
    assert body["truncated_before"] is False and body["truncated_after"] is False


async def test_scope_all_includes_other_devices(async_admin_client: AsyncClient, db_session):
    await _add(db_session, -5, "phone.example", client_ip=PHONE)
    hit = await _add(db_session, 0, "bad.example")

    r = await async_admin_client.get("/api/queries/context", params={"query_id": hit.id, "scope": "all"})

    assert r.status_code == 200, r.text
    assert _domains(r.json()["before"]) == ["phone.example"]


async def test_same_second_lookups_split_around_the_anchor(async_admin_client: AsyncClient, db_session):
    first = await _add(db_session, 0, "first.example")
    hit = await _add(db_session, 0, "bad.example")
    last = await _add(db_session, 0, "last.example")

    body = (await async_admin_client.get("/api/queries/context", params={"query_id": hit.id})).json()

    assert [r["id"] for r in body["before"]] == [first.id]
    assert [r["id"] for r in body["after"]] == [last.id]


async def test_cap_keeps_the_lookups_closest_to_the_anchor(async_admin_client: AsyncClient, db_session):
    for i in range(505):
        db_session.add(Query(timestamp=T0 - timedelta(seconds=250 - i * 0.4), domain=f"d{i}.example",
                             client_ip=LAPTOP, server="pi"))
    await db_session.commit()
    hit = await _add(db_session, 0, "bad.example")

    body = (await async_admin_client.get("/api/queries/context", params={"query_id": hit.id, "window": 5})).json()

    assert body["truncated_before"] is True
    assert len(body["before"]) == 500
    assert body["before"][-1]["domain"] == "d504.example"
    assert "d0.example" not in _domains(body["before"])


async def test_anchor_by_client_time_and_domain(async_admin_client: AsyncClient, db_session):
    await _add(db_session, -60, "bad.example")
    near = await _add(db_session, 3, "bad.example")
    await _add(db_session, 1, "other.example")

    r = await async_admin_client.get("/api/queries/context", params={
        "client_ip": LAPTOP, "at": T0.isoformat(), "domain": "BAD.example",
    })

    assert r.status_code == 200, r.text
    assert r.json()["anchor"]["id"] == near.id


async def test_anchor_by_client_and_time_picks_nearest_lookup(async_admin_client: AsyncClient, db_session):
    await _add(db_session, -30, "far.example")
    near = await _add(db_session, 2, "near.example")

    body = (await async_admin_client.get("/api/queries/context", params={
        "client_ip": LAPTOP, "at": T0.isoformat().replace("+00:00", "Z"),
    })).json()

    assert body["anchor"]["id"] == near.id


async def test_no_lookup_near_the_time_centres_on_it_without_anchor(async_admin_client: AsyncClient, db_session):
    await _add(db_session, -100, "before.example", client_ip=PHONE)

    r = await async_admin_client.get("/api/queries/context", params={
        "client_ip": LAPTOP, "at": T0.isoformat(), "scope": "all",
    })

    assert r.status_code == 200, r.text
    body = r.json()
    assert body["anchor"] is None
    assert body["center"].startswith("2026-11-03T14:03:27")
    assert _domains(body["before"]) == ["before.example"]


async def test_threat_labels_are_included(async_admin_client: AsyncClient, db_session):
    db_session.add(DomainLabel(domain="bad.example", threat_type="malware", threat_source="qfeeds"))
    await db_session.commit()
    hit = await _add(db_session, 0, "bad.example")

    body = (await async_admin_client.get("/api/queries/context", params={"query_id": hit.id})).json()

    assert body["anchor"]["threat_type"] == "malware"


async def test_unknown_query_id_is_404(async_admin_client: AsyncClient):
    r = await async_admin_client.get("/api/queries/context", params={"query_id": 999999})
    assert r.status_code == 404


async def test_needs_query_id_or_client_and_time(async_admin_client: AsyncClient):
    r = await async_admin_client.get("/api/queries/context", params={"client_ip": LAPTOP})
    assert r.status_code == 400


async def test_rejects_unsupported_window(async_admin_client: AsyncClient):
    r = await async_admin_client.get("/api/queries/context", params={"query_id": 1, "window": 7})
    assert r.status_code == 422


async def test_rejects_bad_time(async_admin_client: AsyncClient):
    r = await async_admin_client.get("/api/queries/context", params={"client_ip": LAPTOP, "at": "yesterday"})
    assert r.status_code == 400


async def test_default_window_is_two_minutes(async_admin_client: AsyncClient, db_session):
    await _add(db_session, -150, "outside.example")
    await _add(db_session, -100, "inside.example")
    hit = await _add(db_session, 0, "bad.example")

    body = (await async_admin_client.get("/api/queries/context", params={"query_id": hit.id})).json()

    assert body["window"] == 2
    assert _domains(body["before"]) == ["inside.example"]


async def test_requires_login(async_client: AsyncClient):
    r = await async_client.get("/api/queries/context", params={"query_id": 1})
    assert r.status_code == 401


async def test_out_of_range_time_is_400_not_500(async_admin_client: AsyncClient):
    for at in ("0001-01-01T00:00:00Z", "9999-12-31T23:59:00Z"):
        r = await async_admin_client.get("/api/queries/context", params={"client_ip": LAPTOP, "at": at})
        assert r.status_code == 400, (at, r.status_code, r.text)


async def test_query_id_beyond_bigint_is_rejected(async_admin_client: AsyncClient):
    r = await async_admin_client.get("/api/queries/context", params={"query_id": 2**63})
    assert r.status_code == 422
