from .mqtt import MqttBridge

__red_end_user_data_statement__ = "This cog collects data related to MQTT messages and configurations. It may store a users Discord ID, MQTT topics, and message content for the purpose of bridging Discord and MQTT functionalities. This data is used to facilitate communication between the two platforms and is not shared with third parties."

async def setup(bot):
    await bot.add_cog(MqttBridge(bot))