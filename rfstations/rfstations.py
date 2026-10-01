"""RF Stations: self-service broker logins for the community RF map.

A location is one station on the RF map. Its owner is the member who
created it. A source is one Pi or decoder at the location, with its own
broker login. Members manage both with `/rf`.

The cog never talks to the broker. It calls the community rf-registrar,
which holds the broker's admin key and checks ownership. The cog tells
it who is asking and whether they are an operator.

Passwords are sent by direct message, once, and never stored or shown
in a channel. If the DM cannot be delivered, the new login is revoked
again at once.
"""

import logging
import re
from typing import Any, Dict, Optional
from urllib.parse import quote

import aiohttp
import discord
from redbot.core import Config, commands
from redbot.core.utils.chat_formatting import box, humanize_list

log = logging.getLogger("red.meshtastic.rfstations")

SERVICE = "rfstations"
TOKEN_SERVICE = "rfregistrar"
TIMEOUT = aiohttp.ClientTimeout(total=15)


# The registrar's own rules. Checked here too, so a member gets a plain
# answer and their text never shapes the request.
LOCATION_ID = re.compile(r"^[a-z0-9-]{3,32}$")
SOURCE_ID = re.compile(r"^[a-z0-9][a-z0-9-]{0,15}$")


def seg(text: str) -> str:
    """One URL path segment. A member's text can never add a path or a query."""
    return quote(text, safe="")


def loc(text: str) -> str:
    ident = text.strip().lower()
    if not LOCATION_ID.match(ident):
        raise RegistrarError("A location id is 3 to 32 of a-z, 0-9 and -, such as `tempe-roof`.")
    return seg(ident)


def src(text: str) -> str:
    ident = text.strip().lower()
    if not SOURCE_ID.match(ident):
        raise RegistrarError(
            "A source name is 1 to 16 of a-z, 0-9 and -, not starting with -, such as `adsb-pi`."
        )
    return seg(ident)


class RegistrarError(Exception):
    """The registrar refused, or could not be reached. The text is for the member."""


class RFStations(commands.Cog):
    """Create RF map stations and mint one broker login per Pi."""

    def __init__(self, bot):
        self.bot = bot
        self.config = Config.get_conf(self, identifier=305_202_610, force_registration=True)
        self.config.register_global(registrar_url=None, broker_url=None)
        self.config.register_guild(member_roles=[], operator_roles=[], log_channel=None)
        self.session: Optional[aiohttp.ClientSession] = None

    async def cog_load(self) -> None:
        self.session = aiohttp.ClientSession(timeout=TIMEOUT)

    async def cog_unload(self) -> None:
        if self.session:
            await self.session.close()

    async def red_delete_data_for_user(self, **kwargs) -> None:
        # Nothing is stored here. The registrar keeps ownership records,
        # which an operator can transfer or delete with /rf location.
        return

    # --- who may do what ---------------------------------------------

    async def is_operator(self, ctx: commands.Context) -> bool:
        if await self.bot.is_owner(ctx.author):
            return True
        if ctx.guild is None or not isinstance(ctx.author, discord.Member):
            return False
        if await self.bot.is_admin(ctx.author):
            return True
        roles = set(await self.config.guild(ctx.guild).operator_roles())
        return any(role.id in roles for role in ctx.author.roles)

    async def is_member(self, ctx: commands.Context) -> bool:
        if await self.is_operator(ctx):
            return True
        if ctx.guild is None or not isinstance(ctx.author, discord.Member):
            return False
        roles = set(await self.config.guild(ctx.guild).member_roles())
        return any(role.id in roles for role in ctx.author.roles)

    async def actor(self, ctx: commands.Context) -> Dict[str, Any]:
        return {
            "id": str(ctx.author.id),
            "name": ctx.author.display_name,
            "operator": await self.is_operator(ctx),
        }

    # --- the registrar -----------------------------------------------

    async def call(self, method: str, path: str, body: Optional[dict] = None) -> Any:
        url = await self.config.registrar_url()
        tokens = await self.bot.get_shared_api_tokens(TOKEN_SERVICE)
        key = tokens.get("api_key")
        if not url or not key:
            raise RegistrarError(
                "The RF registrar is not configured yet. Ask an operator to run `rfset`."
            )
        if self.session is None:
            self.session = aiohttp.ClientSession(timeout=TIMEOUT)
        try:
            async with self.session.request(
                method,
                f"{url.rstrip('/')}/v1/{path}",
                json=body,
                headers={"Authorization": f"Bearer {key}"},
            ) as response:
                try:
                    data = await response.json(content_type=None)
                except ValueError:
                    data = None
                if response.status >= 400:
                    if response.status == 401:
                        log.error("the registrar refused the bot's key")
                        raise RegistrarError("The bot's registrar key was refused. Tell an operator.")
                    message = (data or {}).get("error") if isinstance(data, dict) else None
                    raise RegistrarError(message or f"The registrar answered {response.status}.")
                return data
        except aiohttp.ClientError as exc:
            log.warning("registrar unreachable: %s", exc)
            raise RegistrarError("The RF registrar cannot be reached right now. Try again later.")

    async def report(self, ctx: commands.Context, text: str) -> None:
        """Log a change to the operator channel. Never a password."""
        if ctx.guild is None:
            return
        channel_id = await self.config.guild(ctx.guild).log_channel()
        channel = ctx.guild.get_channel(channel_id) if channel_id else None
        if channel is None:
            return
        try:
            await channel.send(
                f"RF: {ctx.author.mention} {text}",
                allowed_mentions=discord.AllowedMentions.none(),
            )
        except discord.HTTPException:
            log.warning("could not write to the RF log channel")

    @staticmethod
    async def reply(ctx: commands.Context, text: str) -> None:
        # Ephemeral for a slash command. A prefix command ignores it.
        await ctx.send(text, ephemeral=True)

    async def guarded(self, ctx: commands.Context) -> Optional[Dict[str, Any]]:
        """The actor, or None after telling a non-member they may not."""
        if not await self.is_member(ctx):
            await self.reply(ctx, "RF station commands are for members with the RF role.")
            return None
        await ctx.defer(ephemeral=True)
        return await self.actor(ctx)

    # --- credentials -------------------------------------------------

    async def send_credentials(self, user: discord.abc.User, creds: Dict[str, str], why: str) -> bool:
        broker = await self.config.broker_url() or "mqtts://<ask an operator>:8883"
        settings = "\n".join(
            [
                f"STATION_ID: {creds['station']}",
                f"SOURCE_ID: {creds['source']}",
                f"BROKER_URL: {broker}",
                f"BROKER_USER: {creds['username']}",
                f"BROKER_PASS: {creds['password']}",
            ]
        )
        text = (
            f"**RF login for `{creds['station']}` / `{creds['source']}`** ({why})\n"
            "Put these in the rf-agent `environment:` on that Pi. "
            "**This password is shown once and is never shown again.** "
            "If you lose it, rotate it with `/rf token rotate`.\n"
            + box(settings, lang="yaml")
        )
        try:
            await user.send(text)
            return True
        except discord.HTTPException:
            return False

    # --- /rf ---------------------------------------------------------

    @commands.hybrid_group(name="rf")
    @commands.guild_only()
    async def rf(self, ctx: commands.Context) -> None:
        """RF map stations and their logins."""

    @rf.group(name="location")
    async def rf_location(self, ctx: commands.Context) -> None:
        """A location is one station on the RF map."""

    @rf_location.command(name="create")
    async def location_create(self, ctx: commands.Context, location: str, *, display_name: str) -> None:
        """Claim a location id, such as tempe-roof. You become its owner.

        The id is 3 to 32 of a-z, 0-9 and -. The display name is shown on the map.
        """
        actor = await self.guarded(ctx)
        if actor is None:
            return
        try:
            made = await self.call(
                "POST", "locations", {"id": location, "display_name": display_name, "actor": actor}
            )
        except RegistrarError as exc:
            await self.reply(ctx, str(exc))
            return
        await self.report(ctx, f"created location `{made['id']}` ({made['display_name']})")
        await self.reply(
            ctx,
            f"Location `{made['id']}` is yours. Mint a login for each Pi with "
            f"`/rf token mint {made['id']} <source>`, such as `adsb-pi` or `sweeper`.",
        )

    @rf_location.command(name="list")
    async def location_list(self, ctx: commands.Context, member: Optional[discord.Member] = None) -> None:
        """Your locations. An operator may name another member."""
        actor = await self.guarded(ctx)
        if actor is None:
            return
        if member is not None and member != ctx.author and not actor["operator"]:
            await self.reply(ctx, "Only an operator may list another member's locations.")
            return
        owner = str((member or ctx.author).id)
        try:
            rows = await self.call("GET", f"locations?owner={owner}")
        except RegistrarError as exc:
            await self.reply(ctx, str(exc))
            return
        if not rows:
            await self.reply(ctx, "No locations. Create one with `/rf location create`.")
            return
        lines = []
        for row in rows:
            sources = [s["source"] for s in row["sources"]]
            lines.append(
                f"{row['id']}  \"{row['display_name']}\"  sources: "
                f"{humanize_list(sources) if sources else 'none'}"
            )
        await self.reply(ctx, box("\n".join(lines)))

    @rf_location.command(name="info")
    async def location_info(self, ctx: commands.Context, location: str) -> None:
        """A location's owner and sources."""
        actor = await self.guarded(ctx)
        if actor is None:
            return
        try:
            row = await self.call("GET", f"locations/{loc(location)}")
        except RegistrarError as exc:
            await self.reply(ctx, str(exc))
            return
        lines = [f"{row['id']}  \"{row['display_name']}\"", f"owner: {row['owner_name']}"]
        for source in row["sources"]:
            lines.append(f"  {source['source']}  login {source['username']}")
        if not row["sources"]:
            lines.append("  no sources yet")
        await self.reply(ctx, box("\n".join(lines)))

    @rf_location.command(name="rename")
    async def location_rename(self, ctx: commands.Context, location: str, *, display_name: str) -> None:
        """Change the name shown on the map."""
        actor = await self.guarded(ctx)
        if actor is None:
            return
        try:
            row = await self.call(
                "POST", f"locations/{loc(location)}/rename", {"display_name": display_name, "actor": actor}
            )
        except RegistrarError as exc:
            await self.reply(ctx, str(exc))
            return
        await self.report(ctx, f"renamed `{row['id']}` to {row['display_name']}")
        await self.reply(ctx, f"`{row['id']}` is now shown as {row['display_name']}.")

    @rf_location.command(name="transfer")
    async def location_transfer(self, ctx: commands.Context, location: str, member: discord.Member) -> None:
        """Hand a location and its logins to another member."""
        actor = await self.guarded(ctx)
        if actor is None:
            return
        if member.bot:
            await self.reply(ctx, "A location cannot belong to a bot.")
            return
        try:
            row = await self.call(
                "POST",
                f"locations/{loc(location)}/transfer",
                {"owner_id": str(member.id), "owner_name": member.display_name, "actor": actor},
            )
        except RegistrarError as exc:
            await self.reply(ctx, str(exc))
            return
        await self.report(ctx, f"transferred `{row['id']}` to {member.mention}")
        await self.reply(ctx, f"`{row['id']}` now belongs to {member.display_name}.")

    @rf_location.command(name="delete")
    async def location_delete(self, ctx: commands.Context, location: str, confirm: str = "") -> None:
        """Remove a location and revoke every login it has.

        Repeat the location id as the last word to confirm.
        """
        actor = await self.guarded(ctx)
        if actor is None:
            return
        if confirm != location:
            await self.reply(
                ctx,
                f"This revokes every login of `{location}` at once. To go ahead: "
                f"`/rf location delete {location} {location}`",
            )
            return
        try:
            await self.call("POST", f"locations/{loc(location)}/delete", {"actor": actor})
        except RegistrarError as exc:
            await self.reply(ctx, str(exc))
            return
        await self.report(ctx, f"deleted location `{location}` and revoked its logins")
        await self.reply(ctx, f"`{location}` is gone, and its logins are revoked.")

    # --- /rf token ---------------------------------------------------

    @rf.group(name="token")
    async def rf_token(self, ctx: commands.Context) -> None:
        """One broker login per Pi or decoder."""

    @rf_token.command(name="mint")
    async def token_mint(self, ctx: commands.Context, location: str, source: str) -> None:
        """Make a login for one Pi, and get it by DM.

        The source names the Pi within the location, such as adsb-pi or sweeper:
        1 to 16 of a-z, 0-9 and -.
        """
        actor = await self.guarded(ctx)
        if actor is None:
            return
        try:
            creds = await self.call(
                "POST", f"locations/{loc(location)}/sources", {"source": source, "actor": actor}
            )
        except RegistrarError as exc:
            await self.reply(ctx, str(exc))
            return
        if not await self.send_credentials(ctx.author, creds, "new"):
            # Nobody has the password now, so the login is useless.
            # Take it away rather than leave it on the broker.
            try:
                await self.call(
                    "POST",
                    f"locations/{seg(creds['station'])}/sources/{seg(creds['source'])}/revoke",
                    {"actor": actor},
                )
            except RegistrarError:
                log.exception("could not revoke an undelivered login %s", creds["username"])
            await self.reply(
                ctx,
                "I could not DM you, so I revoked the new login again. Allow direct "
                "messages from this server, then mint again.",
            )
            return
        await self.report(ctx, f"minted a login for `{creds['station']}` / `{creds['source']}`")
        await self.reply(ctx, f"Sent the login for `{creds['source']}` to your DMs. It is shown once.")

    @rf_token.command(name="list")
    async def token_list(self, ctx: commands.Context, location: str) -> None:
        """The logins of a location."""
        await self.location_info(ctx, location)

    @rf_token.command(name="rotate")
    async def token_rotate(self, ctx: commands.Context, location: str, source: str) -> None:
        """A new password for one Pi. The old one stops working at once."""
        actor = await self.guarded(ctx)
        if actor is None:
            return
        try:
            creds = await self.call(
                "POST", f"locations/{loc(location)}/sources/{src(source)}/rotate", {"actor": actor}
            )
        except RegistrarError as exc:
            await self.reply(ctx, str(exc))
            return
        await self.report(ctx, f"rotated the login of `{creds['station']}` / `{creds['source']}`")
        if not await self.send_credentials(ctx.author, creds, "rotated"):
            await self.reply(
                ctx,
                "The password was changed, but I could not DM you. Allow direct messages "
                "from this server and rotate again.",
            )
            return
        await self.reply(ctx, "Sent the new password to your DMs. The Pi was disconnected until you update it.")

    @rf_token.command(name="revoke")
    async def token_revoke(self, ctx: commands.Context, location: str, source: str) -> None:
        """Remove one Pi's login. It is disconnected at once. Other Pis keep running."""
        actor = await self.guarded(ctx)
        if actor is None:
            return
        try:
            await self.call("POST", f"locations/{loc(location)}/sources/{src(source)}/revoke", {"actor": actor})
        except RegistrarError as exc:
            await self.reply(ctx, str(exc))
            return
        await self.report(ctx, f"revoked the login of `{location}` / `{source}`")
        await self.reply(ctx, f"Revoked `{source}` at `{location}`.")

    # --- [p]rfset ----------------------------------------------------

    @commands.group(name="rfset")
    @commands.admin_or_permissions(manage_guild=True)
    async def rfset(self, ctx: commands.Context) -> None:
        """Configure RF Stations.

        The registrar key is a shared API token:
        `[p]set api rfregistrar api_key,<key>`
        """

    @rfset.command(name="registrar")
    @commands.is_owner()
    async def rfset_registrar(self, ctx: commands.Context, url: str) -> None:
        """The registrar's base URL, such as https://rf-registrar.example."""
        if not url.startswith("https://"):
            await ctx.send("The registrar must be reached over https://.")
            return
        await self.config.registrar_url.set(url.rstrip("/"))
        await ctx.send(f"Registrar set to {url}.")

    @rfset.command(name="broker")
    @commands.is_owner()
    async def rfset_broker(self, ctx: commands.Context, url: str) -> None:
        """The BROKER_URL members put in rf-agent, such as mqtts://broker.example:8883."""
        if not url.startswith("mqtts://"):
            await ctx.send("rf-agent only talks TLS; the URL must start with mqtts://.")
            return
        await self.config.broker_url.set(url)
        await ctx.send(f"Broker set to {url}.")

    @rfset.command(name="memberrole")
    @commands.guild_only()
    async def rfset_memberrole(self, ctx: commands.Context, role: discord.Role) -> None:
        """Add or remove a role whose members may create stations."""
        async with self.config.guild(ctx.guild).member_roles() as roles:
            if role.id in roles:
                roles.remove(role.id)
                await ctx.send(f"{role.name} may no longer create stations.")
            else:
                roles.append(role.id)
                await ctx.send(f"{role.name} may create stations.")

    @rfset.command(name="operatorrole")
    @commands.guild_only()
    async def rfset_operatorrole(self, ctx: commands.Context, role: discord.Role) -> None:
        """Add or remove a role that may manage every station. Admins always may."""
        async with self.config.guild(ctx.guild).operator_roles() as roles:
            if role.id in roles:
                roles.remove(role.id)
                await ctx.send(f"{role.name} is no longer an RF operator role.")
            else:
                roles.append(role.id)
                await ctx.send(f"{role.name} is an RF operator role.")

    @rfset.command(name="logchannel")
    @commands.guild_only()
    async def rfset_logchannel(self, ctx: commands.Context, channel: Optional[discord.TextChannel] = None) -> None:
        """Where every create, mint, rotate and revoke is logged. No channel turns it off."""
        await self.config.guild(ctx.guild).log_channel.set(channel.id if channel else None)
        await ctx.send(f"RF log channel: {channel.mention if channel else 'off'}.")

    @rfset.command(name="settings")
    @commands.guild_only()
    async def rfset_settings(self, ctx: commands.Context) -> None:
        """Show the settings. The key itself is never shown."""
        guild = self.config.guild(ctx.guild)
        tokens = await self.bot.get_shared_api_tokens(TOKEN_SERVICE)

        def roles(ids):
            names = [r.name for r in (ctx.guild.get_role(i) for i in ids) if r]
            return humanize_list(names) if names else "none"

        channel_id = await guild.log_channel()
        log_channel = ctx.guild.get_channel(channel_id) if channel_id else None
        await ctx.send(
            box(
                "\n".join(
                    [
                        f"registrar:      {await self.config.registrar_url() or 'not set'}",
                        f"registrar key:  {'set' if tokens.get('api_key') else 'not set'}",
                        f"broker:         {await self.config.broker_url() or 'not set'}",
                        f"member roles:   {roles(await guild.member_roles())}",
                        f"operator roles: {roles(await guild.operator_roles())}",
                        f"log channel:    {log_channel.mention if log_channel else 'off'}",
                    ]
                )
            )
        )
