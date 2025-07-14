# MqttBridge Cog - Meshtastic Discord Integration

A comprehensive Discord cog that bridges Meshtastic MQTT networks with Discord, providing real-time monitoring, node management, and user interaction features.

## Overview

The MqttBridge cog connects your Discord server to a Meshtastic MQTT broker, enabling seamless integration between your mesh network and Discord community. It automatically processes incoming MQTT messages, stores node information in a local database, and provides rich Discord embeds for network activity.

## Core Features

### MQTT Bridge Functionality
- **Real-time MQTT Integration**: Connects to any MQTT broker to receive Meshtastic network traffic
- **Message Decryption**: Automatically decrypts encrypted Meshtastic messages using configurable keys
- **Multi-channel Support**: Handles messages from different Meshtastic channels
- **Automatic Reconnection**: Robust connection handling with automatic reconnection on failure

### Node Discovery & Management
- **Automatic Node Discovery**: Detects new nodes joining the network and announces them in Discord
- **Node Database**: Maintains a comprehensive SQLite database of all discovered nodes
- **Node Information Tracking**: Stores node details including:
  - Node ID (hex) and Node Number (decimal)
  - Short and long names
  - Hardware model and device role
  - Last seen timestamps
  - Channel information
  - Public keys

### Message Bridging
- **Text Message Relay**: Forwards Meshtastic text messages to designated Discord channels
- **Rich Embeds**: Displays messages in attractive Discord embeds with:
  - Sender information and node details
  - Message content
  - Channel information
  - Gateway details (which node relayed the message)
  - Direct links to MeshView for packet details
- **Duplicate Prevention**: Intelligent filtering to prevent duplicate messages
- **Owner Notifications**: Mentions node owners when their devices send messages (if enabled)

### Telemetry & Position Tracking
- **Telemetry Monitoring**: Captures and stores device telemetry including:
  - Battery level and voltage
  - Temperature, humidity, and pressure readings
  - Channel utilization metrics
  - Device uptime
- **Position Tracking**: Records GPS coordinates and altitude data
- **Historical Data**: Maintains telemetry and position history for analysis

### Traceroute Integration
- **Route Discovery**: Monitors network traceroute packets
- **Visual Feedback**: Creates Discord embeds showing:
  - Source and destination nodes
  - Route participants
  - SNR (Signal-to-Noise Ratio) data
  - Network topology insights
- **MeshView Integration**: Direct links to visualize routes on MeshView

### Node Ownership System
- **Node Claiming**: Users can claim ownership of their nodes through a secure verification process
- **Claim Verification**: Requires sending a unique code from the physical device to prove ownership
- **Ownership Benefits**: 
  - Optional @ mentions for messages/traceroutes from owned nodes
  - Detailed node information access
  - Notification preferences control

### User Commands

#### `/node` Slash Command
- **`/node claim <node_id>`**: Claim ownership of a node
- **`/node list [user]`**: List nodes owned by you or another user
- **`/node info <node_id>`**: Get detailed information about any node
- **`/node stats`**: View network-wide statistics
- **`/node notifications <node_id>`**: Toggle notification preferences for owned nodes

### Administrative Features

#### MQTT Configuration (`!mqtt` commands)
- **`!mqtt setup <broker> [port] [username] [password]`**: Configure MQTT connection
- **`!mqtt topic <topic>`**: Set MQTT subscription topic
- **`!mqtt messageschannel <channel>`**: Set channel for text messages
- **`!mqtt traceroutechannel <channel>`**: Set channel for traceroute messages
- **`!mqtt nodediscoverychannel <channel>`**: Set channel for node discoveries
- **`!mqtt enable/disable`**: Enable/disable the bridge
- **`!mqtt status`**: View current configuration and status

#### Domain Configuration
- **`!mqtt meshviewdomain <domain>`**: Set MeshView instance URL for packet links
- **`!mqtt mapdomain <domain>`**: Set map service URL for location links
- **`!mqtt metricsdomain <domain>`**: Set metrics dashboard URL

#### Node Administration (`!nodeadmin` commands)
- **`!nodeadmin unclaim <node_id>`**: Remove ownership from a node
- **`!nodeadmin setowner <node_id> <user>`**: Manually assign node ownership
- **`!nodeadmin mute <node_id> [type] [reason]`**: Mute nodes from sending messages and/or traceroutes
- **`!nodeadmin unmute <node_id>`**: Remove muting from nodes
- **`!nodeadmin listmuted`**: View all currently muted nodes
- **`!nodeadmin roles [role]`**: List nodes by device role

### Database Features
- **SQLite Storage**: Local database for persistent data storage
- **Comprehensive Tables**: Stores nodes, owners, telemetry, positions, messages, and traceroutes
- **Automatic Cleanup**: Intelligent pruning of old data to manage storage
- **Muting System**: Database-backed node muting for spam prevention

### Advanced Features
- **Message Deduplication**: Prevents duplicate messages from appearing in Discord
- **Gateway Tracking**: Shows which node relayed each message
- **Time Formatting**: Human-readable timestamps ("5 minutes ago")
- **Pagination**: Handles large datasets with paginated Discord embeds
- **Error Handling**: Robust error handling with informative messages
- **Bot Presence**: Updates bot status to show current MQTT broker connection

## Installation Requirements

- Python 3.8+
- Red-DiscordBot framework
- Dependencies:
  - `paho-mqtt` - MQTT client
  - `cryptography` - Message decryption
  - `google.protobuf` - Protocol buffer parsing
  - `meshtastic` - Meshtastic protocol definitions
  - `aiohttp` - HTTP client (for future features)

## Configuration

1. Set up MQTT broker connection with `!mqtt setup`
2. Configure Discord channels for different message types
3. Set domain URLs for external service integration
4. Enable the bridge with `!mqtt enable`
5. Users can claim their nodes with `/node claim`

## Integration Benefits

- **Real-time Monitoring**: See your mesh network activity in Discord
- **Community Building**: Connect mesh users through Discord
- **Network Analytics**: Track node activity and network health
- **User Engagement**: Gamify mesh networking with node ownership
- **Troubleshooting**: Use traceroute data to diagnose network issues
- **External Tools**: Seamless integration with MeshView, maps, and metrics

The MqttBridge cog transforms Discord into a comprehensive dashboard for your Meshtastic network, fostering community engagement while providing powerful monitoring and management capabilities.