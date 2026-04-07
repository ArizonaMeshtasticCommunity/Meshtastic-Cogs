from .strikes import Strikes

__red_end_user_data_statement__ = (
    "This cog stores moderation case data per guild member, including: "
    "user IDs, moderator IDs, case reasons, case types (strike/warning/note), "
    "and timestamps. It also stores a Discord thread ID and message ID used for "
    "case tracking. This data is used solely for moderation purposes within the server."
)


async def setup(bot):
    await bot.add_cog(Strikes(bot))
