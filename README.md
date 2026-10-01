# Installation
Follow the installation steps for [Red-DiscordBot](https://github.com/Cog-Creators/Red-DiscordBot).
Once the bot is installed, run the following command in Discord:

`[p]repo add Meshtastic-Cogs https://github.com/ArizonaMeshtasticCommunity/Meshtastic-Cogs`

## Available Cogs

| Cog Name | Description | Key Features |
|----------|-------------|--------------|
| **mqttbridge** | Bridge between MQTT and Discord for Meshtastic devices | • Real-time MQTT integration<br>• Node discovery & management<br>• Message bridging to Discord<br>• Telemetry & position tracking<br>• Traceroute visualization<br>• Node ownership system<br>• Administrative controls |
| **strikes** | Comprehensive strike, warning, and note tracking system for server moderation | • Three case types: strikes, warnings, and mod notes<br>• Per-member Discord threads for case discussion<br>• Auto-updating anchor embed with case totals<br>• Configurable auto-actions (kick / ban) at strike thresholds<br>• DM notifications to actioned members<br>• Full case history with pagination<br>• Add, view, and remove individual cases |
| **azmsh_welcome** | Automated Welcome messages. | Simply welcomes new members in the welcome channel. |
| **rfstations** | Self-service logins for the community RF map | • `/rf location create` claims a station; you own it<br>• `/rf token mint` makes one broker login per Pi, sent once by DM<br>• Rotate or revoke one Pi without touching the others<br>• Rename, transfer or delete a location<br>• Every change logged to an operator channel<br>• Talks to rf-registrar; the bot never holds the broker's admin key |

## Installation per Cog

After adding the repository, install individual cogs with:

```
[p]cog install Meshtastic-Cogs <cog_name>
```

For example:
```
[p]cog install Meshtastic-Cogs mqttbridge
[p]cog install Meshtastic-Cogs strikes
[p]cog install Meshtastic-Cogs azmsh_welcome
[p]cog install Meshtastic-Cogs rfstations
```

### rfstations setup

The cog calls the community `rf-registrar` (in the `rf-map` repository,
`docs/REGISTRAR.md`), which holds the broker's admin key.

```
[p]set api rfregistrar api_key,<the registrar's REGISTRAR_API_KEY>
[p]rfset registrar https://<registrar host>
[p]rfset broker mqtts://<broker host>:8883
[p]rfset memberrole @RF
[p]rfset operatorrole @Operators
[p]rfset logchannel #rf-log
[p]slash enable rf
[p]slash sync
```

Members with a member role (and every admin or operator) can then use
`/rf location ...` and `/rf token ...`. Passwords go out by DM only, once.