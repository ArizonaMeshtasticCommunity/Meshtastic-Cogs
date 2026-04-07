"""
Strikes — A comprehensive warning and strike tracking system for Red-DiscordBot.

Supports three case types:
  • Strike  — severe action; counts toward configurable auto-action thresholds
  • Warning — formal notice; does NOT count toward thresholds
  • Note    — internal moderator note; never shown to the member

For each member a single forum post (Discord Thread) is created in the
configured Forum Channel.  All cases are logged as replies in that post and
the starter/first message of the post is kept up-to-date with current totals.
If the thread is archived it is automatically unarchived on the next action.
"""

import asyncio
import discord

from datetime import datetime, timezone
from typing import Optional

from redbot.core import commands, Config
from redbot.core.bot import Red
from redbot.core.utils.menus import menu, DEFAULT_CONTROLS


# ── Constants ────────────────────────────────────────────────────────────────

CASE_COLORS: dict[str, discord.Color] = {
    "strike": discord.Color.red(),
    "warning": discord.Color.yellow(),
    "note": discord.Color.blurple(),
}

CASE_EMOJIS: dict[str, str] = {
    "strike": "⚠️",
    "warning": "🟡",
    "note": "📝",
}

VALID_ACTIONS = ("kick", "ban")

CASES_PER_PAGE = 5


# ── Cog ──────────────────────────────────────────────────────────────────────


class Strikes(commands.Cog):
    """
    A comprehensive warning and strike tracking system.

    Track strikes, warnings, and moderator notes for server members.
    Maintains a dedicated Discord thread per member in a configured channel
    for case discussion and record-keeping.

    **Quick-start:**
    1. `[p]strikeset channel #your-forum-channel` — set up the case forum channel.
    2. `[p]strikeset threshold add 3 kick` — optional: auto-kick at 3 strikes.
    3. `[p]strike @User Reason` / `[p]warn @User Reason` — start logging.
    """

    # ── Initialisation ───────────────────────────────────────────────────────

    def __init__(self, bot: Red) -> None:
        self.bot = bot
        self.config = Config.get_conf(
            self, identifier=1738746328, force_registration=True
        )

        self.config.register_guild(
            strike_channel=None,   # ForumChannel ID for case threads
            dm_on_action=True,     # DM member on strike/warning
            thread_prefix="📋 ",   # Prepended to thread names
            thresholds={},         # {str(strike_count): action}
        )

        self.config.register_member(
            cases=[],          # List of case dicts
            thread_id=None,    # ID of the member's forum post (Thread)
            case_count=0,      # Ever-incrementing case counter
        )

    # ── Internal helpers ─────────────────────────────────────────────────────

    async def _add_case(
        self,
        member: discord.Member,
        moderator: discord.Member,
        case_type: str,
        reason: str,
    ) -> dict:
        """Persist a new case and return it."""
        count = await self.config.member(member).case_count()
        case_num = count + 1
        await self.config.member(member).case_count.set(case_num)

        case = {
            "case_num": case_num,
            "type": case_type,
            "reason": reason,
            "mod_id": moderator.id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        async with self.config.member(member).cases() as cases:
            cases.append(case)
        return case

    async def _get_or_create_thread(
        self,
        guild: discord.Guild,
        member: discord.Member,
    ) -> Optional[discord.Thread]:
        """
        Return the member's existing forum post (Thread), or create a new one.

        Each member gets a single forum post inside the configured ForumChannel.
        The starter/first message of that post acts as the live summary and is
        updated on every case action.  Subsequent cases are posted as replies.
        Returns None if no forum channel is configured or creation fails.
        """
        channel_id = await self.config.guild(guild).strike_channel()
        if not channel_id:
            return None

        channel = guild.get_channel(channel_id)
        if not isinstance(channel, discord.ForumChannel):
            return None

        # ── Try to find an existing forum post ──────────────────────────────
        thread_id = await self.config.member(member).thread_id()
        if thread_id:
            thread = guild.get_thread(thread_id)
            if thread is None:
                try:
                    thread = await self.bot.fetch_channel(thread_id)
                except (discord.NotFound, discord.HTTPException):
                    thread = None

            if isinstance(thread, discord.Thread):
                if thread.archived:
                    try:
                        await thread.edit(archived=False)
                    except (discord.Forbidden, discord.HTTPException):
                        pass  # Sending a message will auto-unarchive anyway
                return thread
            # Post was deleted externally — fall through to recreate

        # ── Create a new forum post ──────────────────────────────────────────
        prefix = await self.config.guild(guild).thread_prefix()
        thread_name = f"{prefix}{member.display_name}"[:100]

        # The starter message of the forum post serves as the live summary.
        # ForumChannel.create_thread() returns a ThreadWithMessage namedtuple;
        # we must access .thread to get the actual discord.Thread object.
        # In Discord's API the starter message ID equals the thread ID.
        starter_embed = self._build_anchor_embed(member, strikes=0, warnings=0, notes=0)
        try:
            result = await channel.create_thread(
                name=thread_name,
                embed=starter_embed,
                auto_archive_duration=10080,  # 7 days
                reason=f"Case thread for {member} ({member.id})",
            )
            thread = result.thread
        except (discord.HTTPException, discord.Forbidden):
            return None

        await self.config.member(member).thread_id.set(thread.id)
        return thread

    @staticmethod
    def _build_anchor_embed(
        member: discord.Member,
        strikes: int,
        warnings: int,
        notes: int,
        recent_cases: Optional[list] = None,
    ) -> discord.Embed:
        """Build the starter-message embed for the member's forum post."""
        embed = discord.Embed(
            title=f"📋 {member.display_name}",
            description=(
                f"{member.mention}  •  `{member.id}`\n"
                "This thread tracks all moderation cases for this member.\n"
                "New cases are logged here automatically."
            ),
            color=discord.Color.dark_orange(),
            timestamp=datetime.now(timezone.utc),
        )
        embed.set_thumbnail(url=member.display_avatar.url)
        embed.add_field(name="⚠️ Strikes", value=str(strikes), inline=True)
        embed.add_field(name="🟡 Warnings", value=str(warnings), inline=True)
        embed.add_field(name="📝 Notes", value=str(notes), inline=True)
        embed.add_field(
            name="Account Created",
            value=discord.utils.format_dt(member.created_at, "R"),
            inline=True,
        )
        if member.joined_at:
            embed.add_field(
                name="Joined Server",
                value=discord.utils.format_dt(member.joined_at, "R"),
                inline=True,
            )

        if recent_cases:
            lines = [
                f"{CASE_EMOJIS.get(c['type'], '❓')} **#{c['case_num']}** "
                f"{c['reason'][:55]}{'…' if len(c['reason']) > 55 else ''}"
                for c in reversed(recent_cases[-3:])
            ]
            embed.add_field(name="Recent Cases", value="\n".join(lines), inline=False)

        embed.set_footer(text="Last updated")
        return embed

    async def _update_anchor(
        self, guild: discord.Guild, member: discord.Member
    ) -> None:
        """
        Edit the starter message of the member's forum post with fresh case counts.

        In Discord forum channels the starter message ID equals the thread ID,
        so we fetch it directly from the thread with that ID.
        """
        thread_id = await self.config.member(member).thread_id()
        if not thread_id:
            return

        try:
            thread = await self.bot.fetch_channel(thread_id)
            if not isinstance(thread, discord.Thread):
                return

            cases = await self.config.member(member).cases()
            strikes = sum(1 for c in cases if c["type"] == "strike")
            warnings = sum(1 for c in cases if c["type"] == "warning")
            notes = sum(1 for c in cases if c["type"] == "note")

            embed = self._build_anchor_embed(
                member,
                strikes=strikes,
                warnings=warnings,
                notes=notes,
                recent_cases=cases,
            )
            # Starter message ID == thread ID in forum posts
            starter_msg = await thread.fetch_message(thread_id)
            await starter_msg.edit(embed=embed)
        except (discord.NotFound, discord.HTTPException):
            pass

    async def _post_case_to_thread(
        self,
        thread: discord.Thread,
        case: dict,
        member: discord.Member,
        moderator: discord.Member,
    ) -> None:
        """Send a formatted case embed to the member's thread."""
        color = CASE_COLORS.get(case["type"], discord.Color.greyple())
        emoji = CASE_EMOJIS.get(case["type"], "❓")

        embed = discord.Embed(
            title=f"{emoji} {case['type'].title()} — Case #{case['case_num']}",
            color=color,
            timestamp=datetime.fromisoformat(case["timestamp"]),
        )
        embed.set_thumbnail(url=member.display_avatar.url)
        embed.add_field(
            name="Member",
            value=f"{member.mention}\n`{member.id}`",
            inline=True,
        )
        embed.add_field(
            name="Moderator",
            value=f"{moderator.mention}\n`{moderator.id}`",
            inline=True,
        )
        embed.add_field(name="Reason", value=case["reason"], inline=False)
        try:
            await thread.send(embed=embed)
        except discord.HTTPException:
            pass

    async def _check_threshold(
        self,
        ctx: commands.Context,
        member: discord.Member,
        strike_count: int,
    ) -> Optional[str]:
        """
        Apply an automatic action if the current strike count matches a threshold.
        Returns the action string on success, or None if no action was triggered.
        """
        thresholds = await self.config.guild(ctx.guild).thresholds()
        action = thresholds.get(str(strike_count))
        if not action:
            return None
        try:
            if action == "kick":
                await member.kick(
                    reason=f"Automatic action: {strike_count} strike(s) reached"
                )
            elif action == "ban":
                await member.ban(
                    reason=f"Automatic action: {strike_count} strike(s) reached",
                    delete_message_days=0,
                )
            return action
        except (discord.Forbidden, discord.HTTPException):
            return None

    @staticmethod
    def _role_check(ctx: commands.Context, member: discord.Member) -> Optional[str]:
        """
        Return an error string if the author should not be able to action this member,
        or None if the action is permitted.
        """
        if member.bot:
            return "You cannot action bots."
        if member == ctx.author:
            return "You cannot action yourself."
        if (
            ctx.author != ctx.guild.owner
            and member.top_role >= ctx.author.top_role
        ):
            return "You cannot action a member with an equal or higher role."
        return None

    # ── Moderation commands ──────────────────────────────────────────────────

    @commands.guild_only()
    @commands.mod_or_permissions(manage_messages=True)
    @commands.command(name="strike")
    async def cmd_strike(
        self,
        ctx: commands.Context,
        member: discord.Member,
        *,
        reason: str = "No reason provided.",
    ):
        """Issue a **strike** to a member.

        Strikes are the most severe case type and count toward automatic
        thresholds (kick / ban) if they have been configured with
        `[p]strikeset threshold add`.

        **Examples:**
        - `[p]strike @User Repeated harassment`
        - `[p]strike @User`
        """
        err = self._role_check(ctx, member)
        if err:
            return await ctx.send(err)

        async with ctx.typing():
            case = await self._add_case(member, ctx.author, "strike", reason)

            cases = await self.config.member(member).cases()
            strike_count = sum(1 for c in cases if c["type"] == "strike")

            thread = await self._get_or_create_thread(ctx.guild, member)
            if thread:
                await self._post_case_to_thread(thread, case, member, ctx.author)
                await self._update_anchor(ctx.guild, member)

            action_taken = await self._check_threshold(ctx, member, strike_count)

            # DM the member
            if await self.config.guild(ctx.guild).dm_on_action():
                dm = discord.Embed(
                    title=f"⚠️ You received a strike in **{ctx.guild.name}**",
                    description=f"**Reason:** {reason}",
                    color=discord.Color.red(),
                    timestamp=datetime.now(timezone.utc),
                )
                dm.add_field(name="Total Strikes", value=str(strike_count), inline=True)
                if action_taken:
                    dm.add_field(
                        name="Action Taken",
                        value=action_taken.title(),
                        inline=True,
                    )
                try:
                    await member.send(embed=dm)
                except (discord.Forbidden, discord.HTTPException):
                    pass

            # Confirmation embed
            embed = discord.Embed(
                title=f"⚠️ Strike Issued — Case #{case['case_num']}",
                color=discord.Color.red(),
                timestamp=datetime.now(timezone.utc),
            )
            embed.add_field(
                name="Member",
                value=f"{member.mention} (`{member.id}`)",
                inline=True,
            )
            embed.add_field(name="Total Strikes", value=str(strike_count), inline=True)
            embed.add_field(name="Reason", value=reason, inline=False)
            if thread:
                embed.add_field(name="Case Thread", value=thread.mention, inline=True)
            if action_taken:
                embed.add_field(
                    name="Auto-Action",
                    value=f"Member was **{action_taken}**",
                    inline=True,
                )
            embed.set_footer(
                text=f"Moderator: {ctx.author} • Case #{case['case_num']}"
            )
            await ctx.send(embed=embed)

    @commands.guild_only()
    @commands.mod_or_permissions(manage_messages=True)
    @commands.command(name="warn")
    async def cmd_warn(
        self,
        ctx: commands.Context,
        member: discord.Member,
        *,
        reason: str = "No reason provided.",
    ):
        """Issue a **warning** to a member.

        Warnings are less severe than strikes and do **not** count toward
        automatic action thresholds.

        **Examples:**
        - `[p]warn @User Please keep discussions on-topic.`
        - `[p]warn @User`
        """
        err = self._role_check(ctx, member)
        if err:
            return await ctx.send(err)

        async with ctx.typing():
            case = await self._add_case(member, ctx.author, "warning", reason)

            cases = await self.config.member(member).cases()
            warning_count = sum(1 for c in cases if c["type"] == "warning")

            thread = await self._get_or_create_thread(ctx.guild, member)
            if thread:
                await self._post_case_to_thread(thread, case, member, ctx.author)
                await self._update_anchor(ctx.guild, member)

            if await self.config.guild(ctx.guild).dm_on_action():
                dm = discord.Embed(
                    title=f"🟡 You received a warning in **{ctx.guild.name}**",
                    description=f"**Reason:** {reason}",
                    color=discord.Color.yellow(),
                    timestamp=datetime.now(timezone.utc),
                )
                dm.add_field(
                    name="Total Warnings", value=str(warning_count), inline=True
                )
                try:
                    await member.send(embed=dm)
                except (discord.Forbidden, discord.HTTPException):
                    pass

            embed = discord.Embed(
                title=f"🟡 Warning Issued — Case #{case['case_num']}",
                color=discord.Color.yellow(),
                timestamp=datetime.now(timezone.utc),
            )
            embed.add_field(
                name="Member",
                value=f"{member.mention} (`{member.id}`)",
                inline=True,
            )
            embed.add_field(
                name="Total Warnings", value=str(warning_count), inline=True
            )
            embed.add_field(name="Reason", value=reason, inline=False)
            if thread:
                embed.add_field(name="Case Thread", value=thread.mention, inline=True)
            embed.set_footer(
                text=f"Moderator: {ctx.author} • Case #{case['case_num']}"
            )
            await ctx.send(embed=embed)

    @commands.guild_only()
    @commands.mod_or_permissions(manage_messages=True)
    @commands.command(name="modnote")
    async def cmd_note(
        self,
        ctx: commands.Context,
        member: discord.Member,
        *,
        note: str,
    ):
        """Add an internal **moderator note** to a member's case file.

        Notes are **never** communicated to the member.  Use them for
        internal context such as suspected alt accounts, behavioural
        patterns, or ongoing investigations.

        **Example:**
        - `[p]modnote @User Suspected alt of @BannedUser`
        """
        if member.bot:
            return await ctx.send("You cannot add notes for bots.")

        async with ctx.typing():
            case = await self._add_case(member, ctx.author, "note", note)

            thread = await self._get_or_create_thread(ctx.guild, member)
            if thread:
                await self._post_case_to_thread(thread, case, member, ctx.author)
                await self._update_anchor(ctx.guild, member)

            embed = discord.Embed(
                title=f"📝 Note Added — Case #{case['case_num']}",
                color=discord.Color.blurple(),
                timestamp=datetime.now(timezone.utc),
            )
            embed.add_field(
                name="Member",
                value=f"{member.mention} (`{member.id}`)",
                inline=True,
            )
            embed.add_field(name="Note", value=note, inline=False)
            if thread:
                embed.add_field(name="Case Thread", value=thread.mention, inline=True)
            embed.set_footer(
                text=f"Moderator: {ctx.author} • Case #{case['case_num']}"
            )
            await ctx.send(embed=embed)

    # ── History & case management ────────────────────────────────────────────

    @commands.guild_only()
    @commands.mod_or_permissions(manage_messages=True)
    @commands.command(name="history")
    async def cmd_history(
        self,
        ctx: commands.Context,
        member: discord.Member,
    ):
        """View the full case history for a member.

        Shows all strikes, warnings, and notes in a paginated embed.

        **Example:**
        - `[p]history @User`
        """
        cases = await self.config.member(member).cases()
        thread_id = await self.config.member(member).thread_id()

        if not cases:
            embed = discord.Embed(
                title=f"📋 {member.display_name} — No Cases on Record",
                description="This member has a clean record.",
                color=discord.Color.green(),
            )
            embed.set_thumbnail(url=member.display_avatar.url)
            return await ctx.send(embed=embed)

        strikes = sum(1 for c in cases if c["type"] == "strike")
        warnings = sum(1 for c in cases if c["type"] == "warning")
        notes = sum(1 for c in cases if c["type"] == "note")
        total_pages = (len(cases) + CASES_PER_PAGE - 1) // CASES_PER_PAGE

        pages = []
        for page_idx, i in enumerate(range(0, len(cases), CASES_PER_PAGE)):
            batch = cases[i : i + CASES_PER_PAGE]
            embed = discord.Embed(
                title=f"📋 {member.display_name} — Case History",
                color=discord.Color.dark_orange(),
            )
            embed.set_thumbnail(url=member.display_avatar.url)
            embed.add_field(
                name="Totals",
                value=(
                    f"⚠️ Strikes: **{strikes}**  •  "
                    f"🟡 Warnings: **{warnings}**  •  "
                    f"📝 Notes: **{notes}**"
                ),
                inline=False,
            )
            for c in batch:
                ts = datetime.fromisoformat(c["timestamp"])
                emoji = CASE_EMOJIS.get(c["type"], "❓")
                mod = ctx.guild.get_member(c["mod_id"])
                mod_str = mod.mention if mod else f"<@{c['mod_id']}>"
                embed.add_field(
                    name=(
                        f"{emoji} Case #{c['case_num']} — {c['type'].title()}  "
                        f"({discord.utils.format_dt(ts, 'D')})"
                    ),
                    value=f"**Reason:** {c['reason']}\n**By:** {mod_str}",
                    inline=False,
                )
            if thread_id:
                embed.add_field(
                    name="Case Thread",
                    value=f"<#{thread_id}>",
                    inline=False,
                )
            embed.set_footer(
                text=(
                    f"Page {page_idx + 1}/{total_pages}  •  "
                    f"User ID: {member.id}"
                )
            )
            pages.append(embed)

        if len(pages) == 1:
            await ctx.send(embed=pages[0])
        else:
            await menu(ctx, pages, DEFAULT_CONTROLS)

    @commands.guild_only()
    @commands.mod_or_permissions(manage_messages=True)
    @commands.command(name="case")
    async def cmd_case(
        self,
        ctx: commands.Context,
        member: discord.Member,
        case_num: int,
    ):
        """View a specific case by case number.

        **Example:**
        - `[p]case @User 3`
        """
        cases = await self.config.member(member).cases()
        matching = [c for c in cases if c["case_num"] == case_num]
        if not matching:
            return await ctx.send(
                f"Case **#{case_num}** not found for {member.mention}."
            )

        c = matching[0]
        ts = datetime.fromisoformat(c["timestamp"])
        color = CASE_COLORS.get(c["type"], discord.Color.greyple())
        emoji = CASE_EMOJIS.get(c["type"], "❓")
        mod = ctx.guild.get_member(c["mod_id"])
        mod_str = mod.mention if mod else f"<@{c['mod_id']}>"

        embed = discord.Embed(
            title=f"{emoji} Case #{c['case_num']} — {c['type'].title()}",
            color=color,
            timestamp=ts,
        )
        embed.set_thumbnail(url=member.display_avatar.url)
        embed.add_field(
            name="Member",
            value=f"{member.mention} (`{member.id}`)",
            inline=True,
        )
        embed.add_field(name="Moderator", value=mod_str, inline=True)
        embed.add_field(
            name="Date",
            value=discord.utils.format_dt(ts, "F"),
            inline=False,
        )
        embed.add_field(name="Reason", value=c["reason"], inline=False)
        await ctx.send(embed=embed)

    @commands.guild_only()
    @commands.mod_or_permissions(manage_messages=True)
    @commands.command(name="removecase", aliases=["delcase"])
    async def cmd_removecase(
        self,
        ctx: commands.Context,
        member: discord.Member,
        case_num: int,
    ):
        """Remove a specific case from a member's record.

        Use `[p]history @User` to find case numbers.

        **Example:**
        - `[p]removecase @User 4`
        """
        async with self.config.member(member).cases() as cases:
            matching = [c for c in cases if c["case_num"] == case_num]
            if not matching:
                return await ctx.send(
                    f"Case **#{case_num}** not found for {member.mention}."
                )
            removed = matching[0]
            cases.remove(removed)

        await self._update_anchor(ctx.guild, member)

        emoji = CASE_EMOJIS.get(removed["type"], "❓")
        await ctx.send(
            f"✅ Removed **Case #{case_num}** "
            f"({emoji} {removed['type'].title()}) from {member.mention}'s record."
        )

    @commands.guild_only()
    @commands.admin_or_permissions(manage_guild=True)
    @commands.command(name="clearhistory")
    async def cmd_clearhistory(
        self,
        ctx: commands.Context,
        member: discord.Member,
    ):
        """Clear **all** cases from a member's record.

        ⚠️ This action cannot be undone.
        Use `[p]removecase` to remove individual cases instead.

        **Example:**
        - `[p]clearhistory @User`
        """
        cases = await self.config.member(member).cases()
        if not cases:
            return await ctx.send(f"{member.mention} has no cases to clear.")

        await ctx.send(
            f"⚠️ This will permanently delete **{len(cases)}** case(s) for "
            f"{member.mention}.  Reply `yes` to confirm or `no` to cancel."
        )

        def check(m: discord.Message) -> bool:
            return (
                m.author == ctx.author
                and m.channel == ctx.channel
                and m.content.lower() in ("yes", "no")
            )

        try:
            reply = await self.bot.wait_for("message", check=check, timeout=30.0)
        except asyncio.TimeoutError:
            return await ctx.send("Timed out. No changes made.")

        if reply.content.lower() == "no":
            return await ctx.send("Cancelled.")

        await self.config.member(member).cases.set([])
        await self._update_anchor(ctx.guild, member)
        await ctx.send(f"✅ Cleared all cases for {member.mention}.")

    # ── Settings ─────────────────────────────────────────────────────────────

    @commands.guild_only()
    @commands.admin_or_permissions(manage_guild=True)
    @commands.group(name="strikeset")
    async def strikeset(self, ctx: commands.Context):
        """Configure the Strikes cog for this server."""
        if ctx.invoked_subcommand is None:
            await ctx.send_help(ctx.command)

    @strikeset.command(name="channel")
    async def strikeset_channel(
        self,
        ctx: commands.Context,
        channel: Optional[discord.ForumChannel] = None,
    ):
        """Set (or view) the **forum channel** where member case posts will be created.

        The channel must be a **Forum Channel**, not a regular text channel.

        **Examples:**
        - `[p]strikeset channel #mod-cases`
        - `[p]strikeset channel` — show the current channel
        """
        if channel is None:
            cid = await self.config.guild(ctx.guild).strike_channel()
            if cid:
                await ctx.send(f"Current case forum channel: <#{cid}>")
            else:
                await ctx.send(
                    "No case forum channel is configured.  "
                    "Set one with `[p]strikeset channel #forum-channel`."
                )
            return

        await self.config.guild(ctx.guild).strike_channel.set(channel.id)
        await ctx.send(
            f"✅ Case forum channel set to {channel.mention}.  "
            "New member case posts will be created there."
        )

    @strikeset.command(name="removechannel")
    async def strikeset_removechannel(self, ctx: commands.Context):
        """Remove the configured case channel, disabling thread logging."""
        await self.config.guild(ctx.guild).strike_channel.set(None)
        await ctx.send("✅ Case channel removed.  Thread logging is now disabled.")

    @strikeset.command(name="dm")
    async def strikeset_dm(self, ctx: commands.Context, enabled: bool):
        """Toggle whether members receive a DM when actioned.

        **Examples:**
        - `[p]strikeset dm true`
        - `[p]strikeset dm false`
        """
        await self.config.guild(ctx.guild).dm_on_action.set(enabled)
        await ctx.send(
            f"✅ DM notifications {'**enabled**' if enabled else '**disabled**'}."
        )

    @strikeset.command(name="prefix")
    async def strikeset_prefix(self, ctx: commands.Context, *, prefix: str):
        """Set the prefix prepended to case thread names.

        **Examples:**
        - `[p]strikeset prefix 🚨 `
        - `[p]strikeset prefix [Case] `
        """
        await self.config.guild(ctx.guild).thread_prefix.set(prefix)
        await ctx.send(f"✅ Thread prefix set to: `{prefix}`")

    @strikeset.group(name="threshold", invoke_without_command=True)
    async def strikeset_threshold(self, ctx: commands.Context):
        """Manage automatic actions triggered at specific strike counts."""
        await ctx.send_help(ctx.command)

    @strikeset_threshold.command(name="add")
    async def threshold_add(
        self,
        ctx: commands.Context,
        strike_count: int,
        action: str,
    ):
        """Set an automatic action that fires when a member reaches a strike count.

        Valid actions: `kick`, `ban`

        **Examples:**
        - `[p]strikeset threshold add 3 kick`
        - `[p]strikeset threshold add 5 ban`
        """
        action = action.lower()
        if action not in VALID_ACTIONS:
            return await ctx.send(
                f"Invalid action `{action}`.  "
                f"Valid options: {', '.join(f'`{a}`' for a in VALID_ACTIONS)}"
            )
        if strike_count < 1:
            return await ctx.send("Strike count must be 1 or greater.")

        async with self.config.guild(ctx.guild).thresholds() as thresholds:
            thresholds[str(strike_count)] = action

        await ctx.send(
            f"✅ At **{strike_count}** strike(s) a member will be "
            f"automatically **{action}**ed."
        )

    @strikeset_threshold.command(name="remove")
    async def threshold_remove(self, ctx: commands.Context, strike_count: int):
        """Remove the automatic action at a given strike count.

        **Example:**
        - `[p]strikeset threshold remove 3`
        """
        async with self.config.guild(ctx.guild).thresholds() as thresholds:
            if str(strike_count) not in thresholds:
                return await ctx.send(
                    f"No threshold is configured for **{strike_count}** strike(s)."
                )
            del thresholds[str(strike_count)]

        await ctx.send(
            f"✅ Removed the automatic action for **{strike_count}** strike(s)."
        )

    @strikeset_threshold.command(name="list")
    async def threshold_list(self, ctx: commands.Context):
        """List all configured automatic-action thresholds."""
        thresholds = await self.config.guild(ctx.guild).thresholds()
        if not thresholds:
            return await ctx.send(
                "No thresholds configured.  "
                "Use `[p]strikeset threshold add` to set one."
            )

        embed = discord.Embed(
            title="⚙️ Strike Thresholds",
            color=discord.Color.dark_orange(),
        )
        for count, act in sorted(thresholds.items(), key=lambda x: int(x[0])):
            embed.add_field(
                name=f"{count} Strike(s)",
                value=f"→ **{act.title()}**",
                inline=True,
            )
        await ctx.send(embed=embed)

    @strikeset.command(name="settings")
    async def strikeset_settings(self, ctx: commands.Context):
        """Display the current Strikes configuration for this server."""
        cfg = await self.config.guild(ctx.guild).all()
        cid = cfg["strike_channel"]
        thresholds = cfg["thresholds"]

        threshold_lines = (
            "\n".join(
                f"**{k}** strike(s) → {v.title()}"
                for k, v in sorted(thresholds.items(), key=lambda x: int(x[0]))
            )
            if thresholds
            else "None configured"
        )

        embed = discord.Embed(
            title="⚙️ Strikes — Server Configuration",
            color=discord.Color.dark_orange(),
        )
        embed.add_field(
            name="Case Forum Channel",
            value=f"<#{cid}>" if cid else "Not set",
            inline=False,
        )
        embed.add_field(
            name="DM on Action",
            value="Enabled" if cfg["dm_on_action"] else "Disabled",
            inline=True,
        )
        embed.add_field(
            name="Thread Prefix",
            value=f"`{cfg['thread_prefix']}`",
            inline=True,
        )
        embed.add_field(
            name="Auto-Action Thresholds",
            value=threshold_lines,
            inline=False,
        )
        await ctx.send(embed=embed)
