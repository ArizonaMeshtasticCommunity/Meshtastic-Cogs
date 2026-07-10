from redbot.core import commands, Config
import discord

class Welcome(commands.Cog):
    """Welcome members after onboarding, with duplicate protection."""

    def __init__(self, bot):
        self.bot = bot
        # In-memory cache to track welcomed users this session
        self._welcomed_users = set()
        # Hardcoded welcome channel ID
        self.welcome_channel_id = 1270468564633255936

    @commands.Cog.listener()
    async def on_member_update(self, before: discord.Member, after: discord.Member):
        # Check if the member just finished onboarding
        if before.pending and not after.pending:
            if after.id in self._welcomed_users:
                return  # Already welcomed

            guild = after.guild
            channel = guild.get_channel(self.welcome_channel_id)
            if channel is None:
                return

            # Mark the user as welcomed
            self._welcomed_users.add(after.id)

            await channel.send(
                f"🎉 Welcome to **{guild.name}**, {after.mention}!\n"
                "We're excited to have you here! Please check out <#1274440386827255849> and <#1380219375620980828>.\n\n"
                "Got some nodes already on the mesh? Link them to your Discord! <#1393444182047064084>"
            )