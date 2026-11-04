from datetime import datetime, timedelta, timezone

import pytest
from httpx import AsyncClient
from sqlalchemy import select, text

from backend.geoip import ASN_EDITION, CITY_EDITION
from backend.ingestion import QueryIngestionService
from backend.models import Query
from backend.tests.geoip_helpers import install_fixtures

NOW = datetime.now(timezone.utc).replace(microsecond=0)
GB, SE = "81.2.69.142", "89.160.20.130"


@pytest.fixture
def geoip(isolated_geoip):
    install_fixtures(isolated_geoip, CITY_EDITION, ASN_EDITION)
    isolated_geoip.load()
    return isolated_geoip


def _q(offset: int = 0, domain: str = "example.test", **answers) -> dict:
    return {"timestamp": NOW - timedelta(seconds=offset), "domain": domain, "client": {"ip": "192.168.1.67", "name": ""},
            "type": "A", "status": "ALLOWED", "answer_cnames": [], **answers}


async def _countries(db_session) -> list:
    return [row.answer_countries for row in (await db_session.execute(select(Query).order_by(Query.timestamp))).scalars()]


async def _add(db_session, *rows: Query) -> None:
    db_session.add_all(rows)
    await db_session.commit()


def _row(offset: int = 0, countries=None, server: str = "adguard1", **fields) -> Query:
    return Query(timestamp=NOW - timedelta(seconds=offset), domain=fields.pop("domain", "example.test"),
                 client_ip="192.168.1.67", server=server, answer_countries=countries, **fields)


async def test_ingested_row_gets_the_countries_of_its_answers(geoip, db_session):
    await QueryIngestionService()._store_queries([_q(answer_ips=[GB, SE, GB])], "adguard1")

    assert await _countries(db_session) == [["GB", "SE"]]


async def test_without_geoip_countries_are_null(db_session):
    await QueryIngestionService()._store_queries([_q(answer_ips=[GB])], "adguard1")

    assert await _countries(db_session) == [None]


async def test_asn_only_install_stores_null_not_empty(isolated_geoip, db_session):
    install_fixtures(isolated_geoip, ASN_EDITION)
    isolated_geoip.load()

    await QueryIngestionService()._store_queries([_q(answer_ips=[GB])], "adguard1")

    assert await _countries(db_session) == [None]


async def test_private_and_unknown_answers_store_an_empty_list(geoip, db_session):
    await QueryIngestionService()._store_queries([_q(answer_ips=["192.168.1.1", "10.0.0.5"])], "adguard1")

    assert await _countries(db_session) == [[]]


async def test_mixed_private_and_public_answer_keeps_only_the_public_country(geoip, db_session):
    await QueryIngestionService()._store_queries([_q(answer_ips=["192.168.1.1", SE])], "adguard1")

    assert await _countries(db_session) == [["SE"]]


async def test_blocked_and_pihole_rows_are_never_looked_up(geoip, db_session, monkeypatch):
    def refuse(ips):
        raise AssertionError("looked up a row with no answer addresses")
    monkeypatch.setattr(geoip, "countries", refuse)

    await QueryIngestionService()._store_queries([
        _q(1, domain="blocked.test", answer_ips=[], status="BLOCKED"),
        _q(2, domain="pihole.test"),
    ], "adguard1")

    assert await _countries(db_session) == [None, None]


async def test_ingested_queries_carry_countries(geoip):
    _, stored = await QueryIngestionService()._store_queries([_q(answer_ips=[SE])], "adguard1")

    assert stored[0].answer_countries == ["SE"]


async def test_country_filter_is_case_insensitive(async_admin_client: AsyncClient, db_session):
    await _add(db_session, _row(1, ["GB"], domain="gb.test"), _row(2, ["SE", "GB"], domain="both.test"),
               _row(3, ["SE"], domain="se.test"), _row(4, None, domain="none.test"), _row(5, [], domain="empty.test"))

    for value in ("gb", "GB", "Gb"):
        r = await async_admin_client.get("/api/queries", params={"country": value})
        assert r.status_code == 200, r.text
        assert sorted(q["domain"] for q in r.json()) == ["both.test", "gb.test"]


async def test_count_honours_country_filter(async_admin_client: AsyncClient, db_session):
    await _add(db_session, _row(1, ["GB"], domain="gb.test"), _row(2, ["SE", "GB"], domain="both.test"),
               _row(3, ["SE"], domain="se.test"), _row(4, None, domain="none.test"))

    r = await async_admin_client.get("/api/queries/count", params={"country": "gb"})

    assert r.json() == {"count": 2}
    bad = await async_admin_client.get("/api/queries/count", params={"country": "g"})
    assert bad.status_code == 422


@pytest.mark.parametrize("value", ["g", "gbr", "g1", "é", " g", "%_", "gb\n"])
async def test_country_filter_rejects_anything_but_two_letters(async_admin_client: AsyncClient, value):
    r = await async_admin_client.get("/api/queries", params={"country": value})

    assert r.status_code == 422


async def test_query_rows_expose_countries(async_admin_client: AsyncClient, db_session):
    await _add(db_session, _row(1, ["SE"], domain="a.test"), _row(2, None, domain="b.test"))

    rows = {q["domain"]: q for q in (await async_admin_client.get("/api/queries")).json()}

    assert rows["a.test"]["answer_countries"] == ["SE"]
    assert rows["b.test"]["answer_countries"] is None


async def test_context_rows_expose_countries(async_admin_client: AsyncClient, db_session):
    await _add(db_session, _row(0, ["SE"], domain="anchor.test"), _row(5, ["GB"], domain="before.test"))
    anchor = (await db_session.execute(select(Query).where(Query.domain == "anchor.test"))).scalar_one()

    body = (await async_admin_client.get("/api/queries/context", params={"query_id": anchor.id})).json()

    assert body["anchor"]["answer_countries"] == ["SE"]
    assert body["before"][0]["answer_countries"] == ["GB"]


async def test_stats_count_queries_per_country(async_admin_client: AsyncClient, db_session):
    await _add(db_session, _row(1, ["SE"], domain="a"), _row(2, ["SE", "GB"], domain="b"), _row(3, ["GB"], domain="c"),
               _row(4, ["SE"], domain="d"), _row(5, None, domain="e"), _row(6, [], domain="f"),
               _row(7, ["ZZ"], domain="g"))

    r = await async_admin_client.get("/api/statistics/countries")

    assert r.status_code == 200, r.text
    assert r.json() == [
        {"country": "SE", "country_name": "Sweden", "count": 3},
        {"country": "GB", "country_name": "United Kingdom", "count": 2},
        {"country": "ZZ", "country_name": None, "count": 1},
    ]


async def test_stats_break_ties_by_code(async_admin_client: AsyncClient, db_session):
    await _add(db_session, _row(1, ["SE"], domain="a"), _row(2, ["DE"], domain="b"), _row(3, ["GB"], domain="c"))

    r = await async_admin_client.get("/api/statistics/countries")

    assert [c["country"] for c in r.json()] == ["DE", "GB", "SE"]


async def test_stats_return_the_top_twenty(async_admin_client: AsyncClient, db_session):
    codes = [a + b for a in "ABC" for b in "ABCDEFG"]
    await _add(db_session, *[_row(i, [code], domain=f"d{i}") for i, code in enumerate(codes)])

    r = await async_admin_client.get("/api/statistics/countries")

    assert len(r.json()) == 20


async def test_stats_honour_servers_and_clients(async_admin_client: AsyncClient, db_session):
    await _add(db_session, _row(1, ["SE"], server="adguard1", domain="a"), _row(2, ["GB"], server="adguard2", domain="b"),
               Query(timestamp=NOW - timedelta(seconds=3), domain="c", client_ip="192.168.1.99", server="adguard1",
                     answer_countries=["US"]))

    by_server = await async_admin_client.get("/api/statistics/countries", params={"servers": "adguard2"})
    by_client = await async_admin_client.get("/api/statistics/countries", params={"clients": "192.168.1.99"})

    assert [c["country"] for c in by_server.json()] == ["GB"]
    assert [c["country"] for c in by_client.json()] == ["US"]


async def test_stats_honour_the_period(async_admin_client: AsyncClient, db_session):
    await _add(db_session, _row(1, ["SE"], domain="new"),
               Query(timestamp=NOW - timedelta(days=3), domain="old", client_ip="192.168.1.67", server="adguard1",
                     answer_countries=["GB"]))

    day = await async_admin_client.get("/api/statistics/countries", params={"period": "24h"})
    week = await async_admin_client.get("/api/statistics/countries", params={"period": "7d"})
    custom = await async_admin_client.get("/api/statistics/countries", params={
        "from_date": (NOW - timedelta(days=4)).isoformat(), "to_date": (NOW - timedelta(days=2)).isoformat()})

    assert [c["country"] for c in day.json()] == ["SE"]
    assert sorted(c["country"] for c in week.json()) == ["GB", "SE"]
    assert [c["country"] for c in custom.json()] == ["GB"]


async def test_stats_reject_a_bad_period(async_admin_client: AsyncClient):
    r = await async_admin_client.get("/api/statistics/countries", params={"period": "1y"})

    assert r.status_code == 400


async def test_stats_are_readable_by_any_user(async_readonly_client: AsyncClient, db_session):
    await _add(db_session, _row(1, ["SE"]))

    r = await async_readonly_client.get("/api/statistics/countries")

    assert r.status_code == 200 and r.json()[0]["country"] == "SE"


async def test_stats_require_login(async_client: AsyncClient):
    assert (await async_client.get("/api/statistics/countries")).status_code == 401


async def _seed_pdns(db_session) -> None:
    await _add(db_session, _row(10, domain="geo.test", answer_ips=[SE], answer_cnames=[]),
               _row(20, domain="private.test", answer_ips=["192.168.1.1"], answer_cnames=[]))


async def test_pdns_ip_has_geo(geoip, async_admin_client: AsyncClient, db_session):
    await _seed_pdns(db_session)

    body = (await async_admin_client.get(f"/api/pdns/ip/{SE}")).json()

    assert body["geo"]["asn"] == 29518 and body["geo"]["country"] == "SE"
    assert body["geo"]["country_name"] == "Sweden"


async def test_pdns_ip_without_geoip_has_null_geo(async_admin_client: AsyncClient, db_session):
    await _seed_pdns(db_session)

    body = (await async_admin_client.get(f"/api/pdns/ip/{SE}")).json()

    assert body["geo"] is None


async def test_pdns_domain_rows_have_geo(geoip, async_admin_client: AsyncClient, db_session):
    await _add(db_session, _row(10, domain="both.test", answer_ips=[SE, "192.168.1.1"], answer_cnames=[]))

    body = (await async_admin_client.get("/api/pdns/domain/both.test")).json()

    geo = {row["ip"]: row["geo"] for row in body["ips"]}
    assert geo[SE]["country"] == "SE"
    assert geo["192.168.1.1"] is None


async def test_pdns_resolve_has_geo_with_or_without_a_match(geoip, async_admin_client: AsyncClient, db_session):
    await _seed_pdns(db_session)

    single = (await async_admin_client.get("/api/pdns/resolve", params={"ip": SE})).json()
    miss = (await async_admin_client.get("/api/pdns/resolve", params={"ip": GB})).json()
    batch = (await async_admin_client.post("/api/pdns/resolve", json={"items": [{"ip": SE}, {"ip": "192.168.1.1"}]})).json()

    assert single["match"] == "any" and single["geo"]["country"] == "SE"
    assert miss["match"] == "none" and miss["geo"]["country"] == "GB"
    assert batch["results"][0]["geo"]["country"] == "SE"
    assert batch["results"][1]["geo"] is None


async def test_column_and_index_exist(db_session):
    column = (await db_session.execute(text(
        "SELECT format_type(a.atttypid, a.atttypmod) FROM pg_attribute a "
        "WHERE a.attrelid = 'queries'::regclass AND a.attname = 'answer_countries'"))).scalar()
    index = (await db_session.execute(text(
        "SELECT indexdef FROM pg_indexes WHERE indexname = 'idx_queries_answer_countries'"))).scalar()

    assert column == "character varying(2)[]"
    assert "gin" in index


async def _answer_geo_rows(client, db_session):
    row = _row(0, None, answer_ips=[SE, "192.168.1.5"])
    await _add(db_session, row)
    await db_session.refresh(row)
    search = (await client.get("/api/queries")).json()[0]
    context = (await client.get("/api/queries/context", params={"query_id": row.id})).json()["anchor"]
    return search, context


async def test_rows_carry_read_time_geo_for_public_answer_ips(geoip, async_admin_client: AsyncClient, db_session):
    for body in await _answer_geo_rows(async_admin_client, db_session):
        assert list(body["answer_geo"]) == [SE]
        assert body["answer_geo"][SE]["country"] == "SE"
        assert body["answer_geo"][SE]["asn"] == 29518


async def test_rows_have_no_answer_geo_without_databases(isolated_geoip, async_admin_client: AsyncClient, db_session):
    for body in await _answer_geo_rows(async_admin_client, db_session):
        assert body["answer_geo"] is None


async def test_rows_without_answer_ips_have_no_answer_geo(geoip, async_admin_client: AsyncClient, db_session):
    await _add(db_session, _row(0, None, answer_ips=None), _row(1, None, answer_ips=[], domain="empty.test"))

    assert [q["answer_geo"] for q in (await async_admin_client.get("/api/queries")).json()] == [None, None]
