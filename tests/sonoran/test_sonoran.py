"""The /contributor commands: who may use them, what reaches the registrar, and
that a password only ever reaches a direct message."""

import discord
import pytest
from discord import app_commands

from sonoran.sonoran import RegistrarError, loc, src

from conftest import KEY


def test_the_slash_tree_builds_within_discords_limits(cog):
    tree = app_commands.CommandTree(discord.Client(intents=discord.Intents.none()))
    tree.add_command(cog.contributor.app_command)
    payload = cog.contributor.app_command.to_dict(tree)
    names = []

    def walk(node, prefix=""):
        assert len(node.get("description", "")) <= 100
        names.append(prefix + node["name"])
        for option in node.get("options", []):
            if option.get("type") in (1, 2):
                walk(option, prefix + node["name"] + " ")

    walk(payload)
    for expected in (
        "contributor location create",
        "contributor location delete",
        "contributor token mint",
        "contributor token rotate",
        "contributor token revoke",
    ):
        assert expected in names


@pytest.mark.parametrize("bad", ["..", "x?owner=1", "../locations/victim", "a/b", "ab", "x" * 33])
def test_a_bad_location_never_reaches_a_url(bad):
    with pytest.raises(RegistrarError):
        loc(bad)


@pytest.mark.parametrize("bad", ["..", "-x", "a/b", "a" * 17, "x#"])
def test_a_bad_source_never_reaches_a_url(bad):
    with pytest.raises(RegistrarError):
        src(bad)


def test_good_names_are_lower_cased():
    assert loc("Tempe-Roof") == "tempe-roof"
    assert src(" ADSB-pi ") == "adsb-pi"


async def test_mint_sends_the_password_by_dm_only(cog, ctx, registrar):
    await cog.token_mint.callback(cog, ctx, "tempe-roof", "adsb-pi")

    (method, path, body, auth) = registrar.calls[0]
    assert (method, path) == ("POST", "/v1/locations/tempe-roof/sources")
    assert body["source"] == "adsb-pi" and body["actor"]["id"] == "111"
    assert body["actor"]["operator"] is False
    assert auth == f"Bearer {KEY}"

    (dm,) = ctx.author.dms
    assert "BROKER_PASS: s3cret-password-value" in dm
    assert "BROKER_USER: rf-tempe-roof-adsb-pi" in dm
    assert "SOURCE_ID: adsb-pi" in dm
    assert "BROKER_URL: mqtts://broker.example:8883" in dm
    for text in ctx.replies + ctx.logged:
        assert "s3cret" not in text, "a password reached a channel"
    assert any("minted" in text for text in ctx.logged)


async def test_an_undelivered_login_is_revoked_again(cog, ctx, registrar):
    ctx.author.dm_closed = True
    await cog.token_mint.callback(cog, ctx, "tempe-roof", "sweeper")
    paths = [(m, p) for m, p, _, _ in registrar.calls]
    assert paths == [
        ("POST", "/v1/locations/tempe-roof/sources"),
        ("POST", "/v1/locations/tempe-roof/sources/sweeper/revoke"),
    ]
    assert "revoked" in ctx.replies[-1]
    assert not ctx.logged, "nothing was minted, so nothing is logged as minted"


async def test_a_non_member_is_refused_before_any_request(cog, ctx, registrar):
    from unittest.mock import AsyncMock

    cog.is_member = AsyncMock(return_value=False)
    await cog.token_mint.callback(cog, ctx, "tempe-roof", "adsb-pi")
    assert registrar.calls == []
    assert "contributor role" in ctx.replies[-1]


async def test_bad_input_is_answered_without_a_request(cog, ctx, registrar):
    await cog.token_revoke.callback(cog, ctx, "../locations/victim", "x")
    assert registrar.calls == []
    assert "location id" in ctx.replies[-1]


async def test_delete_needs_the_id_twice(cog, ctx, registrar):
    await cog.location_delete.callback(cog, ctx, "tempe-roof")
    assert registrar.calls == []
    await cog.location_delete.callback(cog, ctx, "tempe-roof", "tempe-roof")
    assert [(m, p) for m, p, _, _ in registrar.calls] == [("POST", "/v1/locations/tempe-roof/delete")]


async def test_registrar_errors_are_passed_on_plainly(cog, ctx, registrar):
    registrar.status = 403
    await cog.token_rotate.callback(cog, ctx, "tempe-roof", "adsb-pi")
    assert ctx.replies[-1] == "nope"
    assert ctx.author.dms == []

    registrar.status = 401
    await cog.token_rotate.callback(cog, ctx, "tempe-roof", "adsb-pi")
    assert "key was refused" in ctx.replies[-1]


async def test_an_unconfigured_registrar_says_so(cog, ctx, conf, registrar):
    await conf.registrar_url.set(None)
    await cog.location_create.callback(cog, ctx, "tempe-roof", display_name="Tempe roof")
    assert registrar.calls == []
    assert "not configured" in ctx.replies[-1]


async def test_operators_and_members_come_from_roles(conf, bot):
    from types import SimpleNamespace
    from unittest.mock import MagicMock

    from sonoran.sonoran import Sonoran

    cog = Sonoran(bot)

    def member(*role_ids):
        m = MagicMock(spec=discord.Member)
        m.roles = [SimpleNamespace(id=r) for r in role_ids]
        return SimpleNamespace(author=m, guild=object())

    assert await cog.is_member(member(42))
    assert not await cog.is_member(member(5))
    assert not await cog.is_operator(member(42))
    await conf.guild(None).operator_roles.set([9])
    assert await cog.is_operator(member(9))
    assert (await cog.actor(member(9)))["operator"] is True


async def test_the_login_dm_names_the_contributor_and_mesh_jobs(cog, ctx, registrar):
    """The Pi runs sonoran-contributor now; mesh jobs are one more setting (Sonoran #178)."""
    await cog.token_mint.callback(cog, ctx, "tempe-roof", "adsb-pi")
    (dm,) = ctx.author.dms
    assert "sonoran-contributor" in dm
    assert "MESH_NODE" in dm
    # A setting the member fills in is not one the bot pretends to know.
    assert "MESH_NODE:" not in dm.split("```")[1]


def test_the_command_is_contributor_and_rf_still_works_as_a_prefix(cog):
    """The service is sonoran-contributor now; /rf was its RF-only name."""
    assert cog.contributor.name == "contributor"
    assert cog.contributor.app_command.name == "contributor"
    assert "rf" in cog.contributor.aliases
    assert cog.rfset.name == "contributorset"
    assert "rfset" in cog.rfset.aliases


async def test_the_login_dm_is_a_contributor_login(cog, ctx, registrar):
    await cog.token_mint.callback(cog, ctx, "tempe-roof", "adsb-pi")
    (dm,) = ctx.author.dms
    assert dm.startswith("**Contributor login for `tempe-roof` / `adsb-pi`**")
    assert "/contributor token rotate" in dm
    assert "/rf " not in dm


# --- Help: a quick start, and no RF-only wording (the rename, #178) -----

from sonoran.sonoran import Sonoran  # noqa: E402

STEPS = ("location create", "token mint", "MESH_NODE", "SOURCES", "logs")


def test_the_cog_help_has_a_quick_start():
    """`[p]help Sonoran` shows the cog's text. The repos are private: it must be enough alone."""
    text = Sonoran.__doc__
    assert "Quick start" in text
    for step in STEPS:
        assert step in text, step


def test_the_contributor_help_has_the_same_quick_start(cog):
    text = cog.contributor.help
    assert "Quick start" in text
    for step in STEPS:
        assert step in text, step


def test_no_help_or_message_still_says_rf_only(cog):
    import inspect

    from sonoran import sonoran as module

    texts = [Sonoran.__doc__] + [c.help or "" for c in cog.walk_commands()]
    source = inspect.getsource(module)
    for old in ("For now: RF map stations", "Configure RF Stations", "RF registrar", "RF role",
                "RF operator role", "RF log channel", "one station on the RF map"):
        assert all(old not in t for t in texts), old
        assert old not in source, old


def _leaves(group):
    return [c for c in group.walk_commands() if not getattr(c, "commands", None)]


def test_the_member_help_lists_every_member_command(cog):
    """`[p]help contributor` names every command a member can run. A new one must be added."""
    text = cog.contributor.help
    for command in _leaves(cog.contributor):
        name = command.qualified_name.split(" ", 1)[1]
        assert name in text, f"`{name}` is missing from the help of contributor"


def test_the_operator_help_has_a_quick_start_and_every_setting(cog):
    text = cog.rfset.help
    assert "Quick start" in text
    assert "set api rfregistrar" in text
    for command in _leaves(cog.rfset):
        assert command.name in text, f"`{command.name}` is missing from the help of contributorset"
    # What an operator may do that a member may not.
    for power in ("any location", "not limited"):
        assert power in text, power
