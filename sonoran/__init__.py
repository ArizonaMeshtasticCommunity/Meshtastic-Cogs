from .sonoran import Sonoran

__red_end_user_data_statement__ = (
    "This cog stores no personal data itself. When a member creates a contributor "
    "station location or a station login, it sends their Discord user ID and "
    "display name to the community's registrar, which records them as the "
    "location's owner and in its change log, with the Discord user ID of whoever "
    "made, rotated or tried each change. The display name is shown on the community "
    "RF map. Station passwords are sent to the member by direct message once and "
    "are never stored."
)


async def setup(bot):
    await bot.add_cog(Sonoran(bot))
