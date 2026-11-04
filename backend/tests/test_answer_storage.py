from datetime import datetime, timedelta, timezone

from sqlalchemy import select, text

from backend.adguard_client import AdGuardHomeClient
from backend.database import engine, ensure_answer_indexes
from backend.ingestion import QueryIngestionService
from backend.models import Query
from backend.technitium_client import TechnitiumClient

T = datetime(2026, 11, 3, 19, 46, 48, 412920, tzinfo=timezone.utc)


def _q(ts: datetime = T, qtype: str = "A", **answers) -> dict:
    return {"timestamp": ts, "domain": "ocsp2.apple.com", "client": {"ip": "192.168.1.67", "name": ""},
            "type": qtype, "status": "ALLOWED", **answers}


async def _rows(db_session) -> list[Query]:
    return list((await db_session.execute(select(Query).order_by(Query.timestamp))).scalars())


async def test_answers_round_trip(db_session):
    await QueryIngestionService()._store_queries(
        [_q(answer_ips=["17.253.23.205", "2001:db8::1"], answer_cnames=["ocsp2.g.aaplimg.com"])], "adguard1")

    row = (await _rows(db_session))[0]
    assert [str(ip) for ip in row.answer_ips] == ["17.253.23.205", "2001:db8::1"]
    assert row.answer_cnames == ["ocsp2.g.aaplimg.com"]


async def test_pihole_rows_have_null_answers(db_session):
    await QueryIngestionService()._store_queries([_q()], "pihole1")

    row = (await _rows(db_session))[0]
    assert row.answer_ips is None and row.answer_cnames is None


async def test_nxdomain_has_empty_not_null(db_session):
    await QueryIngestionService()._store_queries([_q(answer_ips=[], answer_cnames=[])], "adguard1")

    row = (await _rows(db_session))[0]
    assert row.answer_ips == [] and row.answer_cnames == []


async def test_same_key_in_batch_keeps_the_answered_row(db_session):
    count, stored = await QueryIngestionService()._store_queries([
        _q(qtype="HTTPS", answer_ips=[], answer_cnames=["ocsp2.g.aaplimg.com"]),
        _q(qtype="A", answer_ips=["17.253.23.205"], answer_cnames=["ocsp2.g.aaplimg.com"]),
    ], "adguard1")

    rows = await _rows(db_session)
    assert count == 1 and len(stored) == 1
    assert rows[0].query_type == "A" and [str(i) for i in rows[0].answer_ips] == ["17.253.23.205"]


async def test_large_batch_with_answers_fits_the_parameter_limit(db_session):
    queries = [_q(ts=T + timedelta(microseconds=i), answer_ips=["1.1.1.1"], answer_cnames=[]) for i in range(4500)]

    count, _ = await QueryIngestionService()._store_queries(queries, "adguard1")

    assert count == 4500


async def test_ingested_queries_carry_answers(db_session):
    _, stored = await QueryIngestionService()._store_queries([_q(answer_ips=["1.1.1.1"], answer_cnames=[])], "adguard1")

    assert stored[0].answer_ips == ["1.1.1.1"]


def test_adguard_transform_adds_answers():
    q = AdGuardHomeClient("http://a", "pw", "a")._transform_query({
        "time": "2026-11-03T12:46:48.412920678-07:00", "reason": "NotFilteredNotFound",
        "question": {"name": "ocsp2.apple.com", "type": "A"}, "client": "192.168.1.67",
        "answer": [{"type": "CNAME", "value": "ocsp2.g.aaplimg.com."}, {"type": "A", "value": "17.253.23.205"}]})

    assert q["answer_ips"] == ["17.253.23.205"] and q["answer_cnames"] == ["ocsp2.g.aaplimg.com"]


def test_adguard_blocked_transform_has_empty_answers():
    q = AdGuardHomeClient("http://a", "pw", "a")._transform_query({
        "time": "2026-11-03T12:43:37.449673867-07:00", "reason": "FilteredBlackList",
        "question": {"name": "x.minerva.devices.a2z.com", "type": "A"}, "client": "192.168.1.67",
        "answer": [{"type": "A", "value": "0.0.0.0"}]})

    assert q["answer_ips"] == [] and q["answer_cnames"] == []


def test_technitium_transform_adds_answers():
    q = TechnitiumClient("http://t", "tok", "t")._transform_query({
        "timestamp": "2026-11-03T10:00:00Z", "qname": "www.example.com", "clientIpAddress": "192.168.1.5",
        "qtype": "A", "responseType": "Recursive", "answer": "CNAME edge.cdn.net., A 93.184.216.34"})

    assert q["answer_ips"] == ["93.184.216.34"] and q["answer_cnames"] == ["edge.cdn.net"]


async def test_answer_indexes_exist_after_ensure(db_session):
    async with engine.connect() as conn:
        conn = await conn.execution_options(isolation_level="AUTOCOMMIT")
        await conn.execute(text("DROP INDEX IF EXISTS idx_queries_answer_ips"))
        await conn.execute(text("DROP INDEX IF EXISTS idx_queries_answer_cnames"))
        await conn.execute(text("DROP INDEX IF EXISTS idx_queries_answer_countries"))

    await ensure_answer_indexes()

    rows = (await db_session.execute(text(
        "SELECT c.relname, i.indisvalid, am.amname FROM pg_index i JOIN pg_class c ON c.oid = i.indexrelid "
        "JOIN pg_am am ON am.oid = c.relam WHERE c.relname LIKE 'idx_queries_answer_%' ORDER BY 1"))).all()
    assert rows == [("idx_queries_answer_cnames", True, "gin"), ("idx_queries_answer_countries", True, "gin"),
                    ("idx_queries_answer_ips", True, "gin")]


async def test_domains_are_stored_lowercase(db_session):
    await QueryIngestionService()._store_queries([{**_q(), "domain": "WWW.Example.COM"}], "technitium1")

    assert (await _rows(db_session))[0].domain == "www.example.com"


async def test_trailing_dot_is_stripped_from_stored_domains(db_session):
    await QueryIngestionService()._store_queries([{**_q(), "domain": "Example.COM."}], "pihole1")

    assert (await _rows(db_session))[0].domain == "example.com"


async def test_root_zone_keeps_its_spelling(db_session):
    await QueryIngestionService()._store_queries([{**_q(), "domain": "."}], "pihole1")

    assert (await _rows(db_session))[0].domain == "."


async def test_row_with_a_nul_byte_costs_only_that_row(db_session):
    count, _ = await QueryIngestionService()._store_queries([
        {**_q(), "domain": "a\x00b.example.com"},
        {**_q(), "client": {"ip": "192.168.1.67", "name": "bad\x00name"}},
        {**_q(T + timedelta(seconds=1)), "domain": "good.example.com"},
    ], "technitium1")

    assert count == 1
    assert [r.domain for r in await _rows(db_session)] == ["good.example.com"]


async def test_null_text_fields_do_not_fail_the_page(db_session):
    count, _ = await QueryIngestionService()._store_queries(
        [{**_q(), "type": None, "status": None, "client": {"ip": None, "name": None}}], "technitium1")

    assert count == 1


def test_technitium_null_qname_does_not_raise():
    client = TechnitiumClient("http://technitium.test", "token", "tech1")

    assert client._transform_query({"timestamp": "2026-11-03T10:00:00Z", "qname": None})["domain"] == ""


def test_adguard_null_question_does_not_raise():
    client = AdGuardHomeClient("http://adguard.test", "pw", "adguard1")

    assert client._transform_query({"time": "2026-11-03T10:00:00Z", "question": None})["domain"] == ""


async def test_adguard_root_query_is_stored_as_the_root(db_session):
    client = AdGuardHomeClient("http://adguard.test", "pw", "adguard1")
    query = client._transform_query({"time": "2026-11-03T10:00:00Z", "question": {"name": ".", "type": "NS"},
                                     "client": "192.168.1.67"})

    await QueryIngestionService()._store_queries([query], "adguard1")

    assert (await _rows(db_session))[0].domain == "."
