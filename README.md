# Installation
Follow the installation steps for [Red-DiscordBot](https://github.com/Cog-Creators/Red-DiscordBot).
Once the bot is installed, run the following command in Discord:

`[p]repo add Meshtastic-Cogs https://github.com/ArizonaMeshtasticCommunity/Meshtastic-Cogs`

## Available Cogs

| Cog Name | Description | Key Features |
|----------|-------------|--------------|
| **mqttbridge** | Bridge between MQTT and Discord for Meshtastic devices | • Real-time MQTT integration<br>• Node discovery & management<br>• Message bridging to Discord<br>• Telemetry & position tracking<br>• Traceroute visualization<br>• Node ownership system<br>• Administrative controls |

## Installation per Cog

After adding the repository, install individual cogs with:

```
[p]cog install Meshtastic-Cogs <cog_name>
```

For example:
```
[p]cog install Meshtastic-Cogs mqttbridge
```