"""A cog with fake Red pieces, and a fake registrar it talks to over HTTP."""

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import discord
import pytest
import pytest_asyncio
from aiohttp import web
from aiohttp.test_utils import TestServer
from redbot.core import Config

KEY = "k" * 40


class Value:
    """A Red Config value: awaited to read, `.set()` to write."""

    def __init__(self, value):
        self.value = value

    async def __call__(self):
        return self.value

    async def set(self, value):
        self.value = value


class FakeRegistrar:
    """Records each request and answers what the real one would, roughly."""

    def __init__(self):
        self.calls = []
        self.status = None  # force an error status for every call

    def app(self):
        app = web.Application()
        app.router.add_route("*", "/{tail:.*}", self.handle)
        return app

    async def handle(self, request):
        body = await request.json() if request.can_read_body else None
        self.calls.append((request.method, request.path_qs, body, request.headers.get("Authorization")))
        if self.status:
            return web.json_response({"error": "nope"}, status=self.status)
        path = request.path
        if path.endswith("/sources") and request.method == "POST":
            station = path.split("/")[3]
            source = body["source"]
            return web.json_response(
                {
                    "station": station,
                    "source": source,
                    "username": f"rf-{station}-{source}",
                    "password": "s3cret-password-value",
                },
                status=201,
            )
        if path == "/v1/locations" and request.method == "POST":
            return web.json_response({"id": body["id"], "display_name": body["display_name"]}, status=201)
        return web.json_response({"ok": True})


class Member:
    def __init__(self, ident=111, name="Logan", roles=(42,)):
        self.id = ident
        self.display_name = name
        self.mention = f"@{name}"
        self.bot = False
        self.roles = [SimpleNamespace(id=r) for r in roles]
        self.dms = []
        self.dm_closed = False

    async def send(self, text):
        if self.dm_closed:
            raise discord.Forbidden(MagicMock(status=403), "closed")
        self.dms.append(text)


@pytest.fixture
def conf(monkeypatch):
    conf = MagicMock()
    conf.registrar_url = Value(None)
    conf.broker_url = Value("mqtts://broker.example:8883")
    guild = SimpleNamespace(member_roles=Value([42]), operator_roles=Value([]), log_channel=Value(7))
    conf.guild = lambda g: guild
    monkeypatch.setattr(Config, "get_conf", staticmethod(lambda *a, **k: conf))
    return conf


@pytest.fixture
def bot():
    bot = MagicMock()
    bot.get_shared_api_tokens = AsyncMock(return_value={"api_key": KEY})
    bot.is_owner = AsyncMock(return_value=False)
    bot.is_admin = AsyncMock(return_value=False)
    return bot


@pytest_asyncio.fixture
async def registrar():
    fake = FakeRegistrar()
    server = TestServer(fake.app())
    await server.start_server()
    fake.url = str(server.make_url("")).rstrip("/")
    yield fake
    await server.close()


@pytest_asyncio.fixture
async def cog(conf, bot, registrar):
    from sonoran.sonoran import Sonoran

    cog = Sonoran(bot)
    await conf.registrar_url.set(registrar.url)
    await cog.cog_load()
    # The stub author is not a discord.Member; role checks have their own test.
    cog.is_member = AsyncMock(return_value=True)
    yield cog
    await cog.cog_unload()


@pytest.fixture
def ctx():
    replies, logged = [], []
    channel = SimpleNamespace(send=AsyncMock(side_effect=lambda text, **k: logged.append(text)))
    guild = SimpleNamespace(get_channel=lambda i: channel, get_role=lambda i: None)
    context = SimpleNamespace(
        author=Member(),
        guild=guild,
        send=AsyncMock(side_effect=lambda text, **k: replies.append(text)),
        defer=AsyncMock(),
    )
    context.replies, context.logged = replies, logged
    return context
