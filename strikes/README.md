# Strikes

A comprehensive warning and strike tracking system for [Red-DiscordBot](https://github.com/cog-creators/red-discordbot).

Track **strikes**, **warnings**, and **moderator notes** for server members.  For each member a single Discord thread is created in a configured channel.  All cases are logged to that thread and the anchor message in the channel is automatically updated with current totals — giving your mod team a clean at-a-glance directory.

---

## Quick Start

```
[p]strikeset channel #mod-cases
```

The channel must be a **Forum Channel**.  That's it — the cog is now ready.  Optionally configure auto-actions:

```
[p]strikeset threshold add 3 kick
[p]strikeset threshold add 5 ban
```

---

## Case Types

| Type | Command | Counts toward threshold? | DM sent? |
|------|---------|--------------------------|----------|
| ⚠️ Strike | `[p]strike` | ✅ Yes | ✅ Yes (if enabled) |
| 🟡 Warning | `[p]warn` | ❌ No | ✅ Yes (if enabled) |
| 📝 Note | `[p]modnote` | ❌ No | ❌ Never |

---

## Commands

### Moderation  *(requires Mod role or `Manage Messages`)*

| Command | Description |
|---------|-------------|
| `[p]strike <member> [reason]` | Issue a strike |
| `[p]warn <member> [reason]` | Issue a warning |
| `[p]modnote <member> <note>` | Add an internal moderator note |
| `[p]history <member>` | View paginated case history |
| `[p]case <member> <case#>` | View a specific case |
| `[p]removecase <member> <case#>` | Remove a specific case |

### Administration  *(requires Admin role or `Manage Guild`)*

| Command | Description |
|---------|-------------|
| `[p]clearhistory <member>` | Clear **all** cases for a member (with confirmation) |
| `[p]strikeset channel [#forum-channel]` | Set (or view) the case forum channel |
| `[p]strikeset removechannel` | Disable thread logging |
| `[p]strikeset dm <true\|false>` | Toggle DM notifications |
| `[p]strikeset prefix <text>` | Set the case thread name prefix |
| `[p]strikeset threshold add <count> <kick\|ban>` | Add an auto-action at a strike count |
| `[p]strikeset threshold remove <count>` | Remove a threshold |
| `[p]strikeset threshold list` | List all thresholds |
| `[p]strikeset settings` | Show the current server configuration |

---

## How threads work

1. The **first time** a member is actioned, the bot creates a **forum post** in the configured Forum Channel.  The starter/first message of that post is a live summary embed.
2. Every subsequent case for that member is posted as a reply in that existing forum post.
3. The starter message embed is updated automatically to reflect current strike / warning / note totals, member account/join dates, and the three most recent cases.
4. Moderators and admins can use the forum post to discuss cases among themselves.
5. If the post is archived by Discord's auto-archive feature, it is automatically unarchived the next time a case is added.

---

## Installation

```
[p]repo add meshtastic-cogs https://github.com/<your-repo>
[p]cog install meshtastic-cogs strikes
[p]load strikes
```

---

## Permissions Required

| Permission | Reason |
|-----------|--------|
| `Send Messages` | Posting case confirmations and thread messages |
| `Embed Links` | All output uses embeds |
| `Create Public Threads` | Creating per-member case threads |
| `Manage Threads` | Unarchiving threads when a new case is added |
| `Read Message History` | Fetching the anchor message to update it |
| `Kick Members` | Auto-kick threshold action (optional) |
| `Ban Members` | Auto-ban threshold action (optional) |
