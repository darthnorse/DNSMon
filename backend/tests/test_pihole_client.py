import logging

import httpx

from backend.pihole_client import PiholeClient


def _ftl_auth_endpoint(seen: list[httpx.Request]):
    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        if request.method == "DELETE" and request.url.path == "/api/auth":
            if request.headers.get("sid") == "abc":
                return httpx.Response(204)
            return httpx.Response(401)
        return httpx.Response(404)
    return handler


def _client(seen: list[httpx.Request]) -> PiholeClient:
    client = PiholeClient("http://pihole.test", "pw", "pihole1")
    client.client = httpx.AsyncClient(transport=httpx.MockTransport(_ftl_auth_endpoint(seen)))
    return client


async def test_logout_sends_sid_header_and_succeeds(caplog):
    seen: list[httpx.Request] = []
    client = _client(seen)
    client.session_info["sid"] = "abc"
    client.client.cookies.set("sid", "abc")

    with caplog.at_level(logging.WARNING, logger="backend.pihole_client"):
        await client.logout()

    assert len(seen) == 1
    assert seen[0].headers.get("sid") == "abc"
    assert "Logout returned" not in caplog.text


async def test_logout_without_session_makes_no_request():
    seen: list[httpx.Request] = []
    client = _client(seen)

    await client.logout()

    assert seen == []
