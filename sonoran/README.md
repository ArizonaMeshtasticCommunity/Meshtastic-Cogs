# Sonoran

Sonoran, the Arizona Meshtastic Community's observability app, in Discord.

## Installation

```
[p]repo add Meshtastic-Cogs https://github.com/ArizonaMeshtasticCommunity/Meshtastic-Cogs
[p]cog install Meshtastic-Cogs sonoran
[p]load sonoran
```

## Contributor stations

Self-service logins for `sonoran-contributor`, which sends RF data to the
community RF map and does mesh jobs for Sonoran. A **location** is one
station. A **source** is one Pi or decoder there, with its own broker
login.

| Command | What it does |
|---|---|
| `/contributor location create <id> <name>` | Claim a location id, such as `tempe-roof`. You become its owner. |
| `/contributor location list [member]` | Your locations. An operator may name another member. |
| `/contributor location info <id>` | The owner and the sources. |
| `/contributor location rename <id> <name>` | The name shown on the map. |
| `/contributor location transfer <id> <member>` | Hand it, and its logins, to another member. |
| `/contributor location delete <id> <id>` | Remove it and revoke every login. The id twice confirms. |
| `/contributor token mint <location> <source>` | A login for one Pi, such as `adsb-pi`. Sent once by DM. |
| `/contributor token list <location>` | The logins of a location. |
| `/contributor token rotate <location> <source>` | A new password. The old one stops working at once. |
| `/contributor token revoke <location> <source>` | Remove one Pi's login. The other Pis keep running. |

The DM holds the sonoran-contributor settings, ready to paste. It also says how to turn on mesh jobs with `MESH_NODE` (Sonoran #178):

```yaml
STATION_ID: tempe-roof
SOURCE_ID: adsb-pi
BROKER_URL: mqtts://<broker>:8883
BROKER_USER: rf-tempe-roof-adsb-pi
BROKER_PASS: <shown once>
```

If the DM cannot be delivered, the new login is revoked again at once,
because nobody holds its password.

## Setup

The cog never talks to the broker. It calls `rf-registrar` (in
`ArizonaMeshtasticCommunity/sonoran-contributor`, `docs/REGISTRAR.md`), which holds the
broker's admin key and checks who owns what.

```
[p]set api rfregistrar api_key,<the registrar's REGISTRAR_API_KEY>
[p]contributorset registrar https://<registrar host>
[p]contributorset broker mqtts://<broker host>:8883
[p]contributorset memberrole @RF
[p]contributorset operatorrole @Operators
[p]contributorset logchannel #rf-log
[p]slash enable contributor
[p]slash sync
```

- Members with a member role can create and manage their own locations.
- The bot owner, server admins and members with an operator role can
  manage every location, and are not limited by the registrar.
- Every create, mint, rotate, revoke, rename, transfer and delete is
  logged to the log channel. A password never is.

## Development

From the repository root:

```
pip install Red-DiscordBot aiohttp pytest pytest-asyncio flake8
pytest tests/sonoran
```

The tests run the commands against a fake registrar over HTTP.
