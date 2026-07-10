from .azmsh_welcome import Welcome

async def setup(bot):
    await bot.add_cog(Welcome(bot))