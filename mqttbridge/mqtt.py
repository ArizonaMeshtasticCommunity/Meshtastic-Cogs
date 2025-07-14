import asyncio
import aiohttp
import threading
import base64
import os
import sqlite3
import contextlib
from datetime import datetime, timedelta
import discord
import paho.mqtt.client as mqtt
from paho.mqtt.client import CallbackAPIVersion
from redbot.core import commands, Config, app_commands
from redbot.core.utils.menus import menu, DEFAULT_CONTROLS
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import google.protobuf.json_format

import meshtastic
from meshtastic.protobuf import mesh_pb2, mqtt_pb2, telemetry_pb2, portnums_pb2, config_pb2

class MqttBridge(commands.Cog):
    """Bridge between MQTT and Discord for Meshtastic devices"""

    def __init__(self, bot):
        self.bot = bot
        self.config = Config.get_conf(self, identifier=296746788, force_registration=True)
        
        # Default settings
        default_global = {
            "DEFAULT_KEY": "1PG7OiApB1nwvP+rz05pAQ==",
            "mqtt_broker": "localhost",
            "mqtt_port": 1883,
            "mqtt_username": "",
            "mqtt_password": "",
            "mqtt_topic": "msh/#",
            "messages_channel_id": None,
            "traceroute_channel_id": None,
            "nodediscovery_channel_id": None,
            "meshview_domain": None,
            "map_domain": None,
            "metrics_domain": None,
            "enabled": False
        }
        
        self.config.register_global(**default_global)
        
        self.mqtt_client = None
        self.mqtt_thread = None
        self.connected = False
        self.messages_channel = None
        self.traceroute_channel = None
        self.nodediscovery_channel = None
        
        # Setup database
        self.db_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "meshtastic.db")
        asyncio.create_task(self.setup_database())

    @contextlib.contextmanager
    def get_db(self):
        """Context manager for DB Connections"""
        conn = None
        try:
            conn = sqlite3.connect(self.db_path, timeout=30.0)
            conn.execute("PRAGMA busy_timeout = 30000")
            conn.execute("PRAGMA journal_mode=WAL")
            yield conn
        except Exception as e:
            if conn:
                conn.rollback()
            raise
        finally:
            if conn:
                conn.close()

    async def setup_database(self):
        """Initialize the SQLite database and create tables"""
        try:
            with self.get_db() as conn:
                c = conn.cursor()

                # Create nodes table
                c.execute('''
                CREATE TABLE IF NOT EXISTS nodes (
                    node_id TEXT PRIMARY KEY,
                    node_num INTEGER,
                    node_id_hex TEXT,
                    short_name TEXT,
                    long_name TEXT,
                    hw_model TEXT,
                    role TEXT,
                    public_key TEXT,
                    channel TEXT,
                    last_seen TEXT
                )
                ''')

                # Create node_owners table
                c.execute('''
                CREATE TABLE IF NOT EXISTS node_owners (
                    node_id TEXT PRIMARY KEY,
                    discord_id INTEGER,
                    discord_username TEXT,
                    claimed_at TEXT,
                    notifications BOOLEAN DEFAULT FALSE,
                    FOREIGN KEY (node_id) REFERENCES nodes (node_id)
                )
                ''')

                # Create node_telemetry table
                c.execute('''
                CREATE TABLE IF NOT EXISTS node_telemetry (
                    node_id TEXT PRIMARY KEY,
                    timestamp TEXT,
                    battery_level REAL,
                    voltage REAL,
                    temperature REAL,
                    humidity REAL,
                    pressure REAL,
                    channel_utilization REAL,
                    air_util_tx REAL,
                    gas_resistance REAL,
                    uptime_seconds INTEGER,
                    FOREIGN KEY (node_id) REFERENCES nodes (node_id)
                )
                ''')

                # Create node_positions table
                c.execute('''
                CREATE TABLE IF NOT EXISTS node_positions (
                    node_id TEXT PRIMARY KEY,
                    timestamp TEXT,
                    latitude REAL,
                    longitude REAL,
                    altitude REAL,
                    city TEXT,
                    FOREIGN KEY (node_id) REFERENCES nodes (node_id)
                )
                ''')
                
                # Create message_history table
                c.execute('''
                CREATE TABLE IF NOT EXISTS message_history (
                    message_id TEXT PRIMARY KEY,
                    sender_id INTEGER,
                    discord_message_id,
                    message_text TEXT,
                    channel INTEGER,
                    timestamp TEXT
                )
                ''')

                # Create pending_claims table
                c.execute('''
                CREATE TABLE IF NOT EXISTS pending_claims (
                    discord_id INTEGER PRIMARY KEY,
                    node_num INTEGER,
                    code TEXT,
                    username TEXT,
                    expires TEXT
                )
                ''')

                # Create traceroutes table
                c.execute('''
                CREATE TABLE IF NOT EXISTS traceroute (
                    trace_id INTEGER NOT NULL,
                    from_id INTEGER NOT NULL, 
                    to_id INTEGER NOT NULL,
                    timestamp TEXT NOT NULL,
                    PRIMARY KEY (from_id, trace_id, to_id)
                )
                ''')

                # Create traceroute_link table
                c.execute('''
                CREATE TABLE IF NOT EXISTS traceroute_link (
                    trace_id INTEGER NOT NULL,
                    from_id INTEGER NOT NULL, 
                    to_id INTEGER NOT NULL, 
                    link_start INTEGER NOT NULL, 
                    link_end INTEGER NOT NULL, 
                    snr REAL,
                    is_reply INTEGER NOT NULL DEFAULT 0, 
                    is_fast_path INTEGER NOT NULL DEFAULT 0,
                    FOREIGN KEY (from_id, trace_id, to_id) REFERENCES traceroute,
                    PRIMARY KEY (trace_id, from_id, to_id, link_start, link_end, is_reply)
                )
                ''')

                # Create muted_nodes table if it doesn't exist
                c.execute('''
                    CREATE TABLE IF NOT EXISTS muted_nodes (
                        node_id TEXT PRIMARY KEY,
                        mute_traceroute INTEGER DEFAULT 0,
                        mute_messages INTEGER DEFAULT 0,
                        muted_by TEXT,
                        muted_at TEXT,
                        reason TEXT
                    )
                ''')

                conn.commit()
        except Exception as e:
            print(f"Error setting up database: {str(e)}")

    async def cog_load(self):
        """This runs when the cog is loaded/reloaded."""
        asyncio.create_task(self.initialize())

        core_info = self.bot.get_command("info") # Remove this before GitHub, probably needs to be it's own cog...
        if core_info:
            self.bot.remove_command("info")

        contact_command = self.bot.get_command("contact") # Remove this before GitHub, probably needs to be it's own cog...
        if contact_command:
            self.bot.remove_command("contact")

        embedset_command = self.bot.get_command("embedset") # Remove this before GitHub, probably needs to be it's own cog...
        if embedset_command:
            self.bot.remove_command("embedset")

    async def cog_unload(self):
        """Cleanup when the cog is unloaded"""
        if self.mqtt_client and self.connected:
            self.mqtt_client.disconnect()
            self.connected = False
        if self.mqtt_thread and self.mqtt_thread.is_alive():
            self.mqtt_thread.join(timeout=1)

    async def initialize(self):
        """Initialize the MQTT client if enabled"""
        await self.bot.wait_until_ready()

        settings = await self.config.all()
        
        if settings["enabled"]:
            # Set the bot's presence
            await self.bot.change_presence(activity=discord.Activity(
                type=discord.ActivityType.listening, 
                name=f"{settings['mqtt_broker']}"
            ))

            await self.start_mqtt_client()
        else:
            # Set presence to none if not enabled
            await self.bot.change_presence(activity=None)
            
        # Set the discord channels
        if settings["messages_channel_id"]:
            self.messages_channel = self.bot.get_channel(settings["messages_channel_id"])
        if settings["traceroute_channel_id"]:
            self.traceroute_channel = self.bot.get_channel(settings["traceroute_channel_id"])
        if settings["nodediscovery_channel_id"]:
            self.nodediscovery_channel = self.bot.get_channel(settings["nodediscovery_channel_id"])

    async def start_mqtt_client(self):
        """Start the MQTT client in a separate thread"""
        if self.mqtt_thread and self.mqtt_thread.is_alive():
            return
            
        settings = await self.config.all()
        
        # Create MQTT client with protocol version parameter
        self.mqtt_client = mqtt.Client(CallbackAPIVersion.VERSION2, client_id="Discord Meshtastic Bridge")
        
        # Set auth if provided
        if settings["mqtt_username"] and settings["mqtt_password"]:
            self.mqtt_client.username_pw_set(settings["mqtt_username"], settings["mqtt_password"])
        
        # Setup callbacks
        self.mqtt_client.on_connect = self.on_connect
        self.mqtt_client.on_message = self.on_message
        
        try:
            # Start MQTT client in separate thread
            self.mqtt_client.connect(
                settings["mqtt_broker"], 
                settings["mqtt_port"],
                60
            )
            
            # Start the MQTT loop in another thread
            self.mqtt_thread = threading.Thread(target=self.mqtt_client.loop_start, daemon=True)
            self.mqtt_thread.start()

            await self.bot.change_presence(activity=discord.Activity(
                type=discord.ActivityType.listening, 
                name=f"{settings['mqtt_broker']}"
            ))
        except Exception as e:
            print(f"MQTT connection error: {e}")
    
    async def stop_mqtt_client(self):
        """Stop the MQTT client"""
        if self.mqtt_client and self.connected:
            self.mqtt_client.disconnect()
            self.connected = False
            await self.bot.change_presence(activity=None)

    def on_connect(self, client, userdata, flags, rc, properties=None):
        """Callback when MQTT connects - supports both v3 and v5 protocol"""
        if rc == 0:
            self.connected = True
            # Create asyncio task to handle subscription in the event loop
            asyncio.run_coroutine_threadsafe(self.subscribe_to_topic(), self.bot.loop)
        else:
            print(f"Failed to connect to MQTT broker with code {rc}")
    
    async def subscribe_to_topic(self):
        """Subscribe to the MQTT topic"""
        if self.connected:
            settings = await self.config.all()
            self.mqtt_client.subscribe(settings["mqtt_topic"])
            print(f"Subscribed to MQTT topic: {settings['mqtt_topic']}")
    
    def on_message(self, client, userdata, msg):
        """Callback when message is received"""
        asyncio.run_coroutine_threadsafe(
            self.process_mqtt_message(msg),
            self.bot.loop
        )
    
    async def process_mqtt_message(self, msg):
        """Process an MQTT message and forward to Discord"""
            
        settings = await self.config.all()

        # Ignore offline messages
        if msg.payload.startswith(b'offline'):
            return

        se = mqtt_pb2.ServiceEnvelope()
        try:
            se.ParseFromString(msg.payload)
            mp = se.packet
        except Exception as e:
            print(f"Error parsing ServiceEnvelope: {str(e)}")
            return
        
        if mp.HasField("encrypted") and not mp.HasField("decoded"):
            await self.decode_encrypted(mp, se, settings["DEFAULT_KEY"])
        
    async def decode_encrypted(self, mp, se, key):
        """Decrypt a meshtastic message."""

        try:
            if key == "AQ==":
                settings = await self.config.all()
                key = settings["DEFAULT_KEY"]

            # Convert key to bytes
            key_bytes = base64.b64decode(key.encode("ascii"))

            nonce_packet_id = getattr(mp, "id").to_bytes(8, "little")
            nonce_from_node = getattr(mp, "from").to_bytes(8, "little")

            # Put both parts into a single byte array.
            nonce = nonce_packet_id + nonce_from_node

            cipher = Cipher(
                algorithms.AES(key_bytes), modes.CTR(nonce), backend=default_backend()
            )
            decryptor = cipher.decryptor()
            decrypted_bytes = (
                decryptor.update(getattr(mp, "encrypted")) + decryptor.finalize()
            )

            data = mesh_pb2.Data()
            data.ParseFromString(decrypted_bytes)
            mp.decoded.CopyFrom(data)
            
            if mp.decoded.portnum == portnums_pb2.TEXT_MESSAGE_APP:
                # Check if this message is a duplicate before proceeding
                is_duplicate = await self.is_duplicate_message(mp)
                if is_duplicate:
                    return
                
                is_muted = await self.is_node_muted(getattr(mp, "from"), "messages")
                if is_muted:
                    return  # Skip processing
                
                if mp.to != 4294967295:
                    return  # Ignore messages not sent to broadcast
                
                message_text = mp.decoded.payload.decode('utf-8')

                # Store this message in database
                await self.store_message_history(mp, se, message_text)

                # If message starts with CLAIM, process it as a claim and don't send to Discord
                if message_text.startswith("CLAIM-"):
                    await self.check_claim_code(mp)
                    return
            
                await self.send_to_discord(mp, se, message_text)

            if mp.decoded.portnum == portnums_pb2.NODEINFO_APP:
                try:
                    await self.process_node_info(mp, se)
                except Exception as e:
                    print(f"Error processing node info: {str(e)}")

            if mp.decoded.portnum == portnums_pb2.TELEMETRY_APP:
                try:
                    await self.process_telemetry(mp)
                except Exception as e:
                    print(f"Error parsing telemetry data: {str(e)}")

            if mp.decoded.portnum == portnums_pb2.POSITION_APP:
                try:
                    await self.process_position(mp)
                except Exception as e:
                    print(f"Error parsing position data: {str(e)}")

            if mp.decoded.portnum == portnums_pb2.TRACEROUTE_APP:
                try:
                    # Check if this traceroute is a duplicate before proceeding
                    is_duplicate = await self.is_duplicate_traceroute(mp)
                    if is_duplicate:
                        return
                    
                    # Check if the node is muted for traceroute messages
                    is_muted = await self.is_node_muted(getattr(mp, "from"), "traceroute")
                    if is_muted:
                        return  # Skip processing
                    
                    # Store the traceroute data in the database
                    await self.store_traceroute(mp)
                    
                    await self.process_traceroute(mp, se)

                except Exception as e:
                    print(f"Error processing traceroute data: {str(e)}")

        except Exception as e:
            if str(e) == "Error parsing message with type 'meshtastic.protobuf.Data'":
                # Message is a DM, can't be decrypted, and we don't care about it
                return
            else:
                print(f"*** Decryption failed: {str(e)}")

    async def process_node_info(self, mp, se):
        """Process node information and save it to the database"""
        try:
            # Parse the node info from the payload
            node_info = mesh_pb2.User()
            node_info.ParseFromString(mp.decoded.payload)

            # Get sender node ID
            node_id = getattr(mp, "from") if hasattr(mp, "from") else 0
            node_id_hex = format(node_id, 'x')

            # Convert enum values to string representations
            hw_model = node_info.hw_model
            hw_model_str = mesh_pb2.HardwareModel.Name(hw_model) if hasattr(mesh_pb2.HardwareModel, "Name") else "Unknown"
        
            role = node_info.role
            role_str = config_pb2.Config.DeviceConfig.Role.Name(role) if hasattr(config_pb2.Config.DeviceConfig.Role, "Name") else "Unknown"

            # Handle public key if present
            public_key_base64 = None
            if node_info.public_key and len(node_info.public_key) > 0:
                # Convert bytes to base64 string for database storage
                public_key_base64 = base64.b64encode(node_info.public_key).decode('ascii')

            # Check if this is a new node
            is_new_node = await self.is_new_node(str(node_id))
            
            # Save to database
            node_data = {
                "nodeNum": node_id,
                "nodeId": f"!{node_id_hex}",
                "longName": node_info.long_name,
                "shortName": node_info.short_name,
                "hw_model": hw_model_str,
                "role": role_str,
                "channel": se.channel_id,
                "public_key": public_key_base64,
                "last_seen": datetime.now().isoformat(),
            }
            
            await self.save_node_info(str(node_id), node_data)

            # Notify in Discord channel if new node
            if is_new_node:
                settings = await self.config.all()

                # Get gateway ID from ServiceEnvelope
                via = int(se.gateway_id[1:], 16) if hasattr(se, 'gateway_id') and se.gateway_id else None

                with self.get_db() as conn:
                    c = conn.cursor()

                    # Get Gateway node info if available
                    c.execute("""
                        SELECT n.node_id, n.node_num, node_id_hex, short_name, long_name, o.discord_id
                        FROM nodes n
                        LEFT JOIN node_owners o ON n.node_id = o.node_id
                        WHERE n.node_id = ?
                    """, (str(via),))

                    gateway_row = c.fetchone()

                gateway_info = {}
                if gateway_row:
                    gateway_info = {
                        "node_id": gateway_row[0],
                        "node_num": gateway_row[1],
                        "node_id_hex": gateway_row[2],
                        "short_name": gateway_row[3],
                        "long_name": gateway_row[4],
                        "owner": {"discord_id": gateway_row[5]} if gateway_row[5] else None
                    }

                # Process channel information
                channel = se.channel_id

                embed = discord.Embed(
                    title=f"New Node Discovered on {channel}:",
                    description=f"{node_info.long_name} (!{node_id_hex})",
                    color=discord.Color.green(),
                    timestamp=datetime.now()
                )

                embed.add_field(name="Short Name", value=node_info.short_name, inline=True)
                embed.add_field(name="Node Number", value=node_data["nodeNum"], inline=True)
                embed.add_field(name="Node ID", value=f"!{node_id_hex}", inline=True)
                if node_data["role"]:
                    embed.add_field(name="Role", value=node_data["role"], inline=True)
                if node_data["hw_model"]:
                    embed.add_field(name="Hardware", value=node_data["hw_model"], inline=True)
                if via is not None:
                    embed.add_field(
                        name="Seen By", 
                        value=f"{gateway_info.get('long_name', 'Unknown')} ({gateway_info.get('node_id_hex', 'Unknown')})" if gateway_info else via, 
                        inline=True
                    )
                embed.add_field(name="Links", value=f"[View on MeshView]({settings['meshview_domain']}/packet_list/{node_id})", inline=False)

                note = f":warning: If this is your node, type `/node claim !{node_id_hex}` to mark yourself as the owner!"

                if self.nodediscovery_channel:
                    await self.nodediscovery_channel.send(note, embed=embed)
                else:
                    return
            
        except Exception as e:
            if self.nodediscovery_channel:
                await self.nodediscovery_channel.send(f"❌ Error processing node info: {str(e)}")

    async def is_new_node(self, node_id):
        """Check if this node ID exists in the database"""
        try:
            with self.get_db() as conn:
                c = conn.cursor()

                c.execute("SELECT node_id FROM nodes WHERE node_id = ?", (node_id,))
                result = c.fetchone()

            return result is None  # True if node doesn't exist, False otherwise
        except Exception as e:
            print(f"Error checking if node is new: {str(e)}")
            return True  # Assume it's a new node if we can't check
    
    async def save_node_info(self, node_id, node_data):
        """Save node information to the database"""
        try:
            with self.get_db() as conn:
                c = conn.cursor()
    
                # Use INSERT OR REPLACE to update existing or insert new
                c.execute("""
                    INSERT OR REPLACE INTO nodes (
                        node_id, node_num, node_id_hex, short_name, long_name,
                        hw_model, role, channel, public_key, last_seen
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    node_id,
                    node_data.get("nodeNum", 0),
                    node_data.get("nodeId", ""),
                    node_data.get("shortName", ""),
                    node_data.get("longName", ""),
                    node_data.get("hw_model", ""),
                    node_data.get("role", ""),
                    node_data.get("channel", ""),
                    node_data.get("public_key"),
                    node_data.get("last_seen", datetime.now().isoformat())
                ))
    
                conn.commit()
            
        except Exception as e:
            print(f"Error saving node to database: {str(e)}")

    async def send_to_discord(self, mp, se, message_text):
        """Send a decoded Meshtastic message to the configured Discord channel"""
        try:
            # Process channel information
            channel = se.channel_id

            # Get sender info - convert int to hex string
            sender_int = getattr(mp, "from") if hasattr(mp, "from") else 0
            sender_id = format(sender_int, 'x')  # Format as hex string without '0x' prefix

            # Get gateway ID from ServiceEnvelope
            via = int(se.gateway_id[1:], 16) if hasattr(se, 'gateway_id') and se.gateway_id else None

            # Get node info from database
            with self.get_db() as conn:
                c = conn.cursor()
                
                # Get node info
                c.execute("""
                    SELECT n.node_id, n.node_num, n.node_id_hex, n.long_name, n.short_name, o.discord_id, o.notifications
                    FROM nodes n
                    LEFT JOIN node_owners o ON n.node_id = o.node_id
                    WHERE n.node_id = ?
                """, (str(sender_int),))
                
                node_row = c.fetchone()
                
                # Create node_info dict from row
                node_info = {}
                if node_row:
                    node_info = {
                        "nodeId": node_row[2],
                        "longName": node_row[3],
                        "shortName": node_row[4],
                        "owner": {
                            "discord_id": node_row[5],
                            "notifications": bool(node_row[6])
                            } if node_row[5] else None
                    }

                # Get Gateway node info if available
                c.execute("""
                    SELECT n.node_id, n.node_num, node_id_hex, short_name, long_name, o.discord_id
                    FROM nodes n
                    LEFT JOIN node_owners o ON n.node_id = o.node_id
                    WHERE n.node_id = ?
                """, (str(via),))

                gateway_row = c.fetchone()

                gateway_info = {}
                if gateway_row:
                    gateway_info = {
                        "node_id": gateway_row[0],
                        "node_num": gateway_row[1],
                        "node_id_hex": gateway_row[2],
                        "short_name": gateway_row[3],
                        "long_name": gateway_row[4],
                        "owner": {"discord_id": gateway_row[5]} if gateway_row[5] else None
                    }

            settings = await self.config.all()
                
            # Create embed
            embed = discord.Embed(
                title=f"{node_info.get('longName', 'Unknown Node')} (!{sender_id})",
                description=message_text,
                color=discord.Color.green(),
                timestamp=datetime.now()
            )

            embed.add_field(name="Channel", value=channel, inline=True)
            if "owner" in node_info and node_info["owner"]:
                owner_info = node_info["owner"]
                embed.add_field(
                    name="Owner", 
                    value=f"<@{owner_info['discord_id']}>", 
                    inline=True
                )
            if via is not None:
                embed.add_field(
                    name="Via Gateway", 
                    value=f"{gateway_info.get('long_name', 'Unknown')} ({gateway_info.get('node_id_hex', 'Unknown')})" if gateway_info else via, 
                    inline=True
                )
            embed.add_field(name="Links", value=f"[View on MeshView]({settings['meshview_domain']}/packet/{mp.id})", inline=False)
                
            # Send to Discord
            if self.messages_channel:
                if "owner" in node_info and node_info["owner"] and node_info["owner"]["notifications"]:
                    message = await self.messages_channel.send(f"<@{node_info['owner']['discord_id']}>", embed=embed)
                else:
                    message = await self.messages_channel.send(embed=embed)

                with self.get_db() as conn:
                    c = conn.cursor()
                    c.execute("""
                        UPDATE message_history
                        SET discord_message_id = ?
                        WHERE message_id = ?
                    """, (message.id, getattr(mp, "id")))
                    conn.commit()

            else:
                return

        except Exception as e:
            print(f"Error formatting text message: {e}")
            import traceback
            print(traceback.format_exc())
    
    async def process_telemetry(self, mp):
        """Process telemetry information and save it to the database"""
        try:
            # Parse the telemetry from the payload
            telemetry = telemetry_pb2.Telemetry()
            telemetry.ParseFromString(mp.decoded.payload)
            
            # Get sender node ID
            node_id = getattr(mp, "from") if hasattr(mp, "from") else 0
            node_id_str = str(node_id)
            
            # Build telemetry data dictionary based on what fields are present
            telemetry_data = {
                "timestamp": datetime.now().isoformat()
            }
            
            # Add battery info if present
            if telemetry.HasField("device_metrics"):
                if telemetry.device_metrics.HasField("battery_level"):
                    telemetry_data["battery_level"] = telemetry.device_metrics.battery_level
                if telemetry.device_metrics.HasField("voltage"):
                    telemetry_data["voltage"] = telemetry.device_metrics.voltage
                if telemetry.device_metrics.HasField("channel_utilization"):
                    telemetry_data["channel_utilization"] = telemetry.device_metrics.channel_utilization
                if telemetry.device_metrics.HasField("air_util_tx"):
                    telemetry_data["air_util_tx"] = telemetry.device_metrics.air_util_tx
                if telemetry.device_metrics.HasField("uptime_seconds"):
                    telemetry_data["uptime_seconds"] = telemetry.device_metrics.uptime_seconds
        
            # Add environment info if present
            if telemetry.HasField("environment_metrics"):
                if telemetry.environment_metrics.HasField("temperature"):
                    telemetry_data["temperature"] = telemetry.environment_metrics.temperature
                if telemetry.environment_metrics.HasField("relative_humidity"):
                    telemetry_data["humidity"] = telemetry.environment_metrics.relative_humidity
                if telemetry.environment_metrics.HasField("barometric_pressure"):
                    telemetry_data["pressure"] = telemetry.environment_metrics.barometric_pressure
                if telemetry.environment_metrics.HasField("gas_resistance"):
                    telemetry_data["gas_resistance"] = telemetry.environment_metrics.gas_resistance
                
            # Update the node's telemetry information in the database
            await self.update_node_telemetry(node_id_str, telemetry_data)
            
        except Exception as e:
            print(f"Error processing telemetry: {str(e)}")
    
    async def update_node_telemetry(self, node_id, telemetry_data):
        """Update a node's telemetry information in the database"""
        try:
            with self.get_db() as conn:
                c = conn.cursor()

                # Check if node exists in the database first
                c.execute("SELECT node_id FROM nodes WHERE node_id = ?", (node_id,))
                node_exists = c.fetchone()

                if node_exists:
                    # Update the node's last_seen timestamp
                    c.execute("UPDATE nodes SET last_seen = ? WHERE node_id = ?", 
                            (datetime.now().isoformat(), node_id))

                    # Create or update nodes telemetry
                    c.execute("""
                        INSERT OR REPLACE INTO node_telemetry (
                            node_id, timestamp, battery_level, voltage, 
                            temperature, humidity, pressure, 
                            channel_utilization, air_util_tx, gas_resistance, uptime_seconds
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        node_id,
                        telemetry_data.get("timestamp", datetime.now().isoformat()),
                        telemetry_data.get("battery_level"),
                        telemetry_data.get("voltage"),
                        telemetry_data.get("temperature"),
                        telemetry_data.get("humidity"),
                        telemetry_data.get("pressure"),
                        telemetry_data.get("channel_utilization"),
                        telemetry_data.get("air_util_tx"),
                        telemetry_data.get("gas_resistance"),
                        telemetry_data.get("uptime_seconds")
                    ))

                conn.commit()

        except Exception as e:
            print(f"Error updating node telemetry: {str(e)}")

    async def process_position(self, mp):
        """Process position information and save it to the node's entry in the database"""
        try:
            # Parse the position from the payload
            position = mesh_pb2.Position()
            position.ParseFromString(mp.decoded.payload)
            
            # Get sender node ID
            node_id = getattr(mp, "from") if hasattr(mp, "from") else 0
            node_id_str = str(node_id)
            
            # Build position data dictionary based on what fields are present
            position_data = {
                "timestamp": datetime.now().isoformat()
            }

            if position.HasField("latitude_i"):
                position_data["latitude"] = position.latitude_i / 10000000.0
            if position.HasField("longitude_i"):
                position_data["longitude"] = position.longitude_i / 10000000.0
            if position.HasField("altitude"):
                position_data["altitude"] = position.altitude

            # Update the node's position information in the database
            await self.update_node_position(node_id_str, position_data)
            
        except Exception as e:
            print(f"Error processing position: {str(e)}")

    async def update_node_position(self, node_id, position_data):
        """Update a node's position information in the database"""
        try:
            with self.get_db() as conn:
                c = conn.cursor()

                # Check if node exists and update last_seen
                c.execute("SELECT node_id FROM nodes WHERE node_id = ?", (node_id,))
                node_exists = c.fetchone()

                if node_exists:
                    c.execute("UPDATE nodes SET last_seen = ? WHERE node_id = ?", 
                            (datetime.now().isoformat(), node_id))

                    # Create or update nodes position
                    c.execute("""
                        INSERT OR REPLACE INTO node_positions (
                            node_id, timestamp, latitude, longitude, altitude
                        ) VALUES (?, ?, ?, ?, ?)
                    """, (
                        node_id,
                        position_data.get("timestamp", datetime.now().isoformat()),
                        position_data.get("latitude"),
                        position_data.get("longitude"),
                        position_data.get("altitude")
                    ))

                conn.commit()

        except Exception as e:
            print(f"Error updating node position: {str(e)}")

    async def process_traceroute(self, mp, se):
        """Process traceroute"""
        try:
            # Process channel information
            channel = se.channel_id

            # Get sender info - convert int to hex string
            sender_int = getattr(mp, "from") if hasattr(mp, "from") else 0

            # Get receiver info - convert int to hex string
            receiver_int = getattr(mp, "to") if hasattr(mp, "to") else 0

            # Get gateway ID from ServiceEnvelope
            via = int(se.gateway_id[1:], 16) if hasattr(se, 'gateway_id') and se.gateway_id else None

            # Check request_id as an attribute instead of using it directly
            has_request_id = hasattr(mp.decoded, 'request_id') and mp.decoded.request_id
            trace_direction = "REPLY" if has_request_id else "SEND"

            if trace_direction == "SEND":
                with self.get_db() as conn:
                    c = conn.cursor()

                    # Get Sender node info
                    c.execute("""
                        SELECT n.node_id, n.node_num, node_id_hex, short_name, long_name, o.discord_id, o.notifications
                        FROM nodes n
                        LEFT JOIN node_owners o ON n.node_id = o.node_id
                        WHERE n.node_id = ?
                    """, (str(sender_int),))

                    sender_row = c.fetchone()

                    sender_info = {}
                    if sender_row:
                        sender_info = {
                            "node_id": sender_row[0],
                            "node_num": sender_row[1],
                            "node_id_hex": sender_row[2],
                            "short_name": sender_row[3],
                            "long_name": sender_row[4],
                            "owner": {
                                "discord_id": sender_row[5],
                                "notifications": bool(sender_row[6])
                                } if sender_row[5] else None
                        }

                    # Get Receiver node info
                    c.execute("""
                        SELECT n.node_id, n.node_num, node_id_hex, short_name, long_name, o.discord_id
                        FROM nodes n
                        LEFT JOIN node_owners o ON n.node_id = o.node_id
                        WHERE n.node_id = ?
                    """, (str(receiver_int),))

                    receiver_row = c.fetchone()

                    receiver_info = {}
                    if receiver_row:
                        receiver_info = {
                            "node_id": receiver_row[0],
                            "node_num": receiver_row[1],
                            "node_id_hex": receiver_row[2],
                            "short_name": receiver_row[3],
                            "long_name": receiver_row[4],
                            "owner": {"discord_id": receiver_row[5]} if receiver_row[5] else None
                        }

                    # Get Gateway node info if available
                    c.execute("""
                        SELECT n.node_id, n.node_num, node_id_hex, short_name, long_name, o.discord_id
                        FROM nodes n
                        LEFT JOIN node_owners o ON n.node_id = o.node_id
                        WHERE n.node_id = ?
                    """, (str(via),))

                    gateway_row = c.fetchone()

                    gateway_info = {}
                    if gateway_row:
                        gateway_info = {
                            "node_id": gateway_row[0],
                            "node_num": gateway_row[1],
                            "node_id_hex": gateway_row[2],
                            "short_name": gateway_row[3],
                            "long_name": gateway_row[4],
                            "owner": {"discord_id": gateway_row[5]} if gateway_row[5] else None
                        }

                settings = await self.config.all()

                # Create an embed with the traceroute information
                embed = discord.Embed(
                    title=f"Traceroute: {sender_info.get('long_name', 'Unknown')} → {receiver_info.get('long_name', 'Unknown')}",
                    description=f"Trace ID: {mp.id} | Direction: {trace_direction} on Channel: {channel}",
                    color=discord.Color.blue(),
                    timestamp=datetime.now()
                )

                embed.add_field(name="From", value=f"{sender_info.get('long_name', 'Unknown')} ({sender_info.get('node_id_hex', 'Unknown')})", inline=True)
                embed.add_field(name="To", value=f"{receiver_info.get('long_name', 'Unknown')} ({receiver_info.get('node_id_hex', 'Unknown')})", inline=True)
                if via is not None:
                    embed.add_field(
                        name="Via Gateway", 
                        value=f"{gateway_info.get('long_name', 'Unknown')} ({gateway_info.get('node_id_hex', 'Unknown')})" if gateway_info else via, 
                        inline=True
                    )

                if sender_info.get('owner'):
                    embed.add_field(
                        name="Sender Owner", 
                        value=f"<@{sender_info['owner']['discord_id']}>", 
                        inline=True
                    )
                else:
                    embed.add_field(name="\u200b", value="\u200b", inline=True)

                if receiver_info.get('owner'):
                    embed.add_field(
                        name="Receiver Owner", 
                        value=f"<@{receiver_info['owner']['discord_id']}>", 
                        inline=True
                    )
                else:
                    embed.add_field(name="\u200b", value="\u200b", inline=True)

                if gateway_info.get('owner'):
                    embed.add_field(
                        name="Gateway Owner", 
                        value=f"<@{gateway_info['owner']['discord_id']}>", 
                        inline=True
                    )
                else:
                    embed.add_field(name="\u200b", value="\u200b", inline=True)

                embed.add_field(
                    name="Links",
                    value=(
                        f"[View Packet on MeshView]({settings['meshview_domain']}/packet/{mp.id})\n"
                        f"[View Graph on MeshView]({settings['meshview_domain']}/graph/traceroute/{mp.id})\n"
                    ),
                    inline=False
                )

                if self.traceroute_channel:
                    if "owner" in sender_info and sender_info['owner'] and sender_info['owner']['notifications']:
                        await self.traceroute_channel.send(f"<@{sender_info['owner']['discord_id']}>", embed=embed)
                    else:
                        await self.traceroute_channel.send(embed=embed)
                else:
                    return

        except Exception as e:
            print(f"Error processing traceroute: {str(e)}")

    async def store_traceroute(self, mp):
        """Store traceroute information in the database"""
        try:
            with self.get_db() as conn:
                c = conn.cursor()

                # Prepare data for insertion
                trace_id = mp.id
                from_id = getattr(mp, "from", 0)
                to_id = getattr(mp, "to", 0)
                timestamp = datetime.now().isoformat()

                # Insert traceroute data
                c.execute("""
                    INSERT INTO traceroute (trace_id, from_id, to_id, timestamp)
                    VALUES (?, ?, ?, ?)
                """, (trace_id, from_id, to_id, timestamp))

                # Prune old traceroutes (keep last 100)
                c.execute("SELECT COUNT(*) FROM traceroute")
                count = c.fetchone()[0]

                if count > 100:
                    # Delete oldest traceroutes
                    c.execute("""
                        DELETE FROM traceroute
                        WHERE timestamp IN (
                            SELECT timestamp FROM traceroute
                            ORDER BY timestamp ASC
                            LIMIT ?
                        )
                    """, (count - 100,))

                conn.commit()

        except Exception as e:
            print(f"Error storing traceroute: {str(e)}")

    async def is_duplicate_message(self, mp):
        """Check if this message has been seen before"""
        try:
            # Get unique identifiers for this message
            message_id = getattr(mp, "id", 0)
            
            with self.get_db() as conn:
                c = conn.cursor()

                c.execute("SELECT message_id FROM message_history WHERE message_id = ?", (message_id,))
                exists = c.fetchone()

            return exists is not None
            
        except Exception as e:
            print(f"Error checking message history: {str(e)}")
            return False  # If we can't check, assume it's not a duplicate

    async def is_duplicate_traceroute(self, mp):
        """Check if this traceroute has been seen recently"""
        try:
            # Get Unique identifier for the traceroute
            trace_id = mp.id

            with self.get_db() as conn:
                c = conn.cursor()

                c.execute("SELECT trace_id FROM traceroute WHERE trace_id = ?", (trace_id,))
                exists = c.fetchone()

            return exists is not None  # Return True if exists, False otherwise

        except Exception as e:
            print(f"Error checking for duplicate traceroute: {str(e)}")
            return False  # If we can't check, assume it's not a duplicate

    async def is_node_muted(self, node_id, message_type):
        """Check if a node is muted for a specific message type"""
        try:
            with self.get_db() as conn:
                c = conn.cursor()

                if message_type == "traceroute":
                    c.execute("SELECT mute_traceroute FROM muted_nodes WHERE node_id = ?", (node_id,))
                else:  # Regular messages
                    c.execute("SELECT mute_messages FROM muted_nodes WHERE node_id = ?", (node_id,))

                result = c.fetchone()

            return result and result[0] == 1

        except Exception as e:
            print(f"Error checking if node is muted: {str(e)}")
            return False

    async def store_message_history(self, mp, se, message_text):
        """Store message in history to prevent duplicates"""
        try:
            # Get unique identifiers for this message
            message_id = getattr(mp, "id", 0)
            sender_id = getattr(mp, "from", 0)
            timestamp = datetime.now().isoformat()

            # Process channel information
            channel = se.channel_id
            
            with self.get_db() as conn:
                c = conn.cursor()

                # Store message details
                c.execute("""
                    INSERT OR REPLACE INTO message_history (
                        message_id, sender_id, message_text, channel, timestamp
                    ) VALUES (?, ?, ?, ?, ?)
                """, (
                    message_id,
                    sender_id,
                    message_text[:100],  # Store first 100 chars only to save space
                    channel,
                    timestamp
                ))

                # Prune old messages if we have too many (keep last 50)
                c.execute("SELECT COUNT(*) FROM message_history")
                count = c.fetchone()[0]

                if count > 50:
                    # Delete oldest messages to keep only the newest 45
                    c.execute("""
                        DELETE FROM message_history 
                        WHERE timestamp IN (
                            SELECT timestamp FROM message_history 
                            ORDER BY timestamp ASC 
                            LIMIT ?
                        )
                    """, (count - 45,))

                conn.commit()
            
        except Exception as e:
            print(f"Error saving message history: {str(e)}")

    async def check_claim_code(self, mp):
        """Check if the message contains a claim code and process it"""
        try:            
            # Extract message text
            message_text = mp.decoded.payload.decode('utf-8').strip()
            
            # Check if this looks like a claim code (format: CLAIM-XXXX)
            if message_text.startswith("CLAIM-"):
                claim_code = message_text
                sender_node_num = getattr(mp, "from", 0)
                
                with self.get_db() as conn:
                    c = conn.cursor()

                    # Modified query: Allow for string/int conversion issues by casting node_num to string
                    c.execute("""
                        SELECT discord_id, username 
                        FROM pending_claims 
                        WHERE code = ? AND (node_num = ? OR node_num = ?)
                    """, (claim_code, sender_node_num, str(sender_node_num)))

                    claim = c.fetchone()

                    if claim:
                        discord_id, username = claim

                        # Valid claim! Register ownership
                        await self.register_node_owner(
                            str(sender_node_num), 
                            int(discord_id),
                            username
                        )

                        # Remove the pending claim
                        c.execute("DELETE FROM pending_claims WHERE discord_id = ?", (discord_id,))
                        conn.commit()

                        # Notify user via DM
                        try:
                            user = await self.bot.fetch_user(int(discord_id))
                            if user:
                                await user.send(f"✅ Node !{format(sender_node_num, 'x')} has been successfully claimed as your node!")
                        except Exception as e:
                            print(f"Error notifying user: {str(e)}")
            
                conn.close()
                
        except Exception as e:
            print(f"Error checking claim code: {str(e)}")
            import traceback
            traceback.print_exc()  # Print the full stack trace for better debugging

    async def register_node_owner(self, node_id, discord_id, discord_username):
        """Register a Discord user as the owner of a node"""
        try:
            with self.get_db() as conn:
                c = conn.cursor()

                # Check if node exists
                c.execute("SELECT node_id FROM nodes WHERE node_id = ?", (node_id,))
                node_exists = c.fetchone()

                if node_exists:
                    # Update or insert owner information
                    c.execute("""
                        INSERT OR REPLACE INTO node_owners (
                            node_id, discord_id, discord_username, claimed_at
                        ) VALUES (?, ?, ?, ?)
                    """, (
                        node_id,
                        discord_id,
                        discord_username,
                        datetime.now().isoformat()
                    ))

                    # Check if Pending Claim exists
                    c.execute("SELECT node_num FROM pending_claims WHERE node_num = ?", (node_id,))
                    claim_exists = c.fetchone()

                    if claim_exists:
                        # Remove the pending claim
                        c.execute("DELETE FROM pending_claims WHERE node_num = ?", (node_id,))

                    conn.commit()

                return True

            return False
            
        except Exception as e:
            print(f"Error registering node owner: {str(e)}")
            return False

    async def generate_claim_code(self, node_num, discord_id):
        """Generate a unique claim code for a node"""
        # Simple code generation - combine node number, user ID and a timestamp, then hash
        # We'll make it readable by using a subset of the hash
        timestamp = int(datetime.now().timestamp())
        combined = f"{node_num}-{discord_id}-{timestamp}"
        
        import hashlib
        hash_obj = hashlib.sha256(combined.encode())
        code = f"CLAIM-{hash_obj.hexdigest()[:8].upper()}"
        
        try:
            with self.get_db() as conn:
                c = conn.cursor()

                # Store new claim
                c.execute("""
                    INSERT OR REPLACE INTO pending_claims (
                        discord_id, node_num, code, username, expires
                    ) VALUES (?, ?, ?, ?, ?)
                """, (
                    discord_id,
                    node_num,
                    code,
                    str(self.bot.get_user(discord_id)),
                    (datetime.now() + timedelta(minutes=30)).isoformat()
                ))

                conn.commit()
            
        except Exception as e:
            print(f"Error saving claim code: {str(e)}")
        
        return code

    def format_uptime(self, uptime_seconds):
        """Format uptime seconds into a human-readable string"""
        if uptime_seconds is None:
            return "Unknown"

        days = uptime_seconds // 86400
        hours = (uptime_seconds % 86400) // 3600
        minutes = (uptime_seconds % 3600) // 60
        seconds = uptime_seconds % 60

        parts = []
        if days > 0:
            parts.append(f"{days}d")
        if hours > 0:
            parts.append(f"{hours}h")
        if minutes > 0:
            parts.append(f"{minutes}m")
        if seconds > 0 or not parts:  # Show seconds if it's the only unit or if nothing else
            parts.append(f"{seconds}s")

        return " ".join(parts)

    def format_time_ago(self, timestamp_str):
        """Convert a timestamp to a human-readable 'time ago' string
    
        Args:
            timestamp_str: ISO format timestamp string
            
        Returns:
            String like '5 minutes ago', '2 hours ago', etc.
        """
        try:
            timestamp = datetime.fromisoformat(timestamp_str)
            time_diff = datetime.now() - timestamp
            
            if time_diff.days > 0:
                if time_diff.days == 1:
                    return "1 day ago"
                return f"{time_diff.days} days ago"
            elif time_diff.seconds >= 3600:
                hours = time_diff.seconds // 3600
                if hours == 1:
                    return "1 hour ago"
                return f"{hours} hours ago"
            elif time_diff.seconds >= 60:
                minutes = time_diff.seconds // 60
                if minutes == 1:
                    return "1 minute ago"
                return f"{minutes} minutes ago"
            else:
                if time_diff.seconds == 1:
                    return "1 second ago"
                return f"{time_diff.seconds} seconds ago"
        except Exception as e:
            print(f"Error formatting timestamp: {str(e)}")
            return "Unknown time"

    def create_node_pages(self, nodes, title, nodes_per_page=10):
        """Helper method to create embed pages for node listings"""
        pages = []
        
        # Split nodes into chunks for pages
        node_chunks = [nodes[i:i+nodes_per_page] for i in range(0, len(nodes), nodes_per_page)]
        
        for i, chunk in enumerate(node_chunks):
            embed = discord.Embed(
                title=title,
                color=discord.Color.blue(),
                timestamp=datetime.now()
            )
            
            for node_hex, long_name, short_name, last_seen, channel in chunk:
                # Create field for each node
                field_name = f"{long_name} ({node_hex})"
                
                # Format last seen time
                last_seen_str = self.format_time_ago(last_seen) if last_seen else "Never"
                
                field_value = f"Short name: {short_name}\nChannel: {channel}\nLast seen: {last_seen_str}"
                embed.add_field(name=field_name, value=field_value, inline=True)
            
            # Add page number
            embed.set_footer(text=f"Page {i+1}/{len(node_chunks)}")
            pages.append(embed)
        
        return pages

    # MQTT bridge commands
    @commands.group(name="mqtt")
    @commands.admin()
    async def mqtt(self, ctx: commands.Context):
        """MQTT bridge configuration commands"""
    
    @mqtt.command(name="setup")
    async def setup_bridge(self, ctx: commands.Context, broker: str, port: int = 1883, 
                           username: str = "", password: str = ""):
        """Set up the MQTT broker connection"""
        await self.config.mqtt_broker.set(broker)
        await self.config.mqtt_port.set(port)
        await self.config.mqtt_username.set(username)
        await self.config.mqtt_password.set(password)
        
        await ctx.send(f"MQTT broker set to {broker}:{port}")
        
    @mqtt.command(name="topic")
    async def set_topic(self, ctx: commands.Context, topic: str):
        """Set the MQTT topic to subscribe to (default: msh/#)"""
        await self.config.mqtt_topic.set(topic)
        await ctx.send(f"MQTT topic set to {topic}")
        
        # Resubscribe if connected
        if self.connected:
            self.mqtt_client.subscribe(topic)
    
    @mqtt.command(name="messageschannel")
    async def set_messages_channel(self, ctx: commands.Context, channel: discord.TextChannel = None):
        """Set the Discord channel for MQTT messages"""

        if channel:
            await self.config.messages_channel_id.set(channel.id)
            self.messages_channel = channel
            await ctx.send(f"Messages will be sent to {channel.mention}")
        else:
            await ctx.send("Messages channel cleared.")

    @mqtt.command(name="traceroutechannel")
    async def set_traceroute_channel(self, ctx: commands.Context, channel: discord.TextChannel = None):
        """Set the Discord channel for MQTT traceroute messages"""
        if channel:
            await self.config.traceroute_channel_id.set(channel.id)
            self.traceroute_channel = channel
            await ctx.send(f"Traceroute messages will be sent to {channel.mention}")
        else:
            await ctx.send("Traceroute channel cleared.")

    @mqtt.command(name="nodediscoverychannel")
    async def set_node_discovery_channel(self, ctx: commands.Context, channel: discord.TextChannel = None):
        """Set the Discord channel for MQTT node discovery messages"""
        if channel:
            await self.config.nodediscovery_channel_id.set(channel.id)
            self.nodediscovery_channel = channel
            await ctx.send(f"Node discovery messages will be sent to {channel.mention}")
        else:
            await ctx.send("Node discovery channel cleared.")

    @mqtt.command(name="meshviewdomain")
    async def set_meshview_domain(self, ctx: commands.Context, domain: str):
        """Set the meshview domain for links"""
        await self.config.meshview_domain.set(domain)
        await ctx.send(f"Links will use meshview domain: {domain}")

    @mqtt.command(name="mapdomain")
    async def set_map_domain(self, ctx: commands.Context, domain: str):
        """Set the map domain for links"""
        await self.config.map_domain.set(domain)
        await ctx.send(f"Links will use map domain: {domain}")

    @mqtt.command(name="metricsdomain")
    async def set_metrics_domain(self, ctx: commands.Context, domain: str):
        """Set the metrics domain for links"""
        await self.config.metrics_domain.set(domain)
        await ctx.send(f"Links will use metrics domain: {domain}")

    @mqtt.command(name="enable")
    async def enable_bridge(self, ctx: commands.Context):
        """Enable the MQTT bridge"""
        await self.config.enabled.set(True)
        await self.start_mqtt_client()
        
        await ctx.send("MQTT bridge enabled")
    
    @mqtt.command(name="disable")
    async def disable_bridge(self, ctx: commands.Context):
        """Disable the MQTT bridge"""
        await self.config.enabled.set(False)
        await self.stop_mqtt_client()
        
        await ctx.send("MQTT bridge disabled")
    
    @mqtt.command(name="status")
    async def bridge_status(self, ctx: commands.Context):
        """Show the status of the MQTT bridge"""
        settings = await self.config.all()
        
        embed = discord.Embed(
            title="MQTT Bridge Status",
            color=discord.Color.blue() if settings["enabled"] else discord.Color.red()
        )
        
        embed.add_field(name="Status", value="Enabled" if settings["enabled"] else "Disabled")
        embed.add_field(name="Connected", value="Yes" if self.connected else "No")
        embed.add_field(name="MQTT Broker", value=f"{settings['mqtt_broker']}:{settings['mqtt_port']}")
        embed.add_field(name="MQTT Topic", value=settings["mqtt_topic"])
        
        if settings["messages_channel_id"]:
            channel = self.bot.get_channel(settings["messages_channel_id"])
            channel_mention = channel.mention if channel else "Channel not found"
            embed.add_field(name="Messages Channel", value=channel_mention)

        if settings["traceroute_channel_id"]:
            channel = self.bot.get_channel(settings["traceroute_channel_id"])
            channel_mention = channel.mention if channel else "Channel not found"
            embed.add_field(name="Traceroutes Channel", value=channel_mention)

        if settings["nodediscovery_channel_id"]:
            channel = self.bot.get_channel(settings["nodediscovery_channel_id"])
            channel_mention = channel.mention if channel else "Channel not found"
            embed.add_field(name="Node Discovery Channel", value=channel_mention)

        if settings["meshview_domain"]:
            embed.add_field(name="Meshview Domain", value=settings["meshview_domain"])

        if settings["map_domain"]:
            embed.add_field(name="Map Domain", value=settings["map_domain"])

        if settings["metrics_domain"]:
            embed.add_field(name="Metrics Domain", value=settings["metrics_domain"])
        
        
        await ctx.send(embed=embed)

    # Node management commands
    @app_commands.command(name="node")
    @app_commands.describe(
        action="Action to perform",
        node_identifier="Node identifier (NodeNum or NodeID with ! prefix)",
        user="User involved in the action (for list)"
    )
    @app_commands.choices(action=[
        app_commands.Choice(name="claim", value="claim"),
        app_commands.Choice(name="list", value="list"),
        app_commands.Choice(name="info", value="info"),
        app_commands.Choice(name="stats", value="stats"),
        app_commands.Choice(name="notifications", value="notifications")
    ])
    async def node_command(self, interaction: discord.Interaction,
                           action: str,
                           node_identifier: str = None,
                           user: discord.Member = None):
        """Node management commands"""
        await interaction.response.defer(thinking=True)

        try:
            if action == "claim":
                # Handle claim action
                await self.claim_node(interaction, node_identifier)
            elif action == "list":
                # Handle list action
                await self.list_owned_nodes(interaction, user or interaction.user)
            elif action == "info":
                # Handle info action
                await self.node_id_lookup(interaction, node_identifier)
            elif action == "stats":
                await self.node_stats(interaction)
            elif action == "notifications":
                await self.toggle_node_notifications(interaction, node_identifier)
            else:
                await interaction.followup.send(f"Unknown action: {action}", ephemeral=True)
        except Exception as e:
            await interaction.followup.send(f"Error: {str(e)}", ephemeral=True)

    async def claim_node(self, interaction: discord.Interaction, node_identifier: str):
        """Claim a node as yours"""
        try:            
            node_num = None
            found_node = False
            node_data = {}
            
            try:
                with self.get_db() as conn:
                    c = conn.cursor()

                    # Check if we're looking for a node ID (hex with ! prefix)
                    if node_identifier.startswith('!'):
                        hex_id = node_identifier.lower()
                        # Search through nodes to find matching nodeId
                        c.execute("""
                            SELECT n.node_num, n.node_id_hex, n.long_name, o.discord_id
                            FROM nodes n 
                            LEFT JOIN node_owners o ON n.node_id = o.node_id 
                            WHERE n.node_id_hex = ?
                        """, (hex_id,))
                        node_row = c.fetchone()
                        if node_row:
                            found_node = True
                            node_num = node_row[0]  # node_num
                            node_data = {
                                "nodeId": node_row[1],
                                "longName": node_row[2],
                                "owner_id": node_row[3]  # discord_id from JOIN
                            }
                    else:
                        # Assume it's a node number (decimal)
                        try:
                            node_num = int(node_identifier)
                            c.execute("""
                                SELECT n.node_num, n.node_id_hex, n.long_name, o.discord_id
                                FROM nodes n 
                                LEFT JOIN node_owners o ON n.node_id = o.node_id 
                                WHERE n.node_num = ?
                            """, (node_num,))
                            node_row = c.fetchone()
                            if node_row:
                                found_node = True
                                node_data = {
                                    "nodeId": node_row[1],
                                    "longName": node_row[2],
                                    "owner_id": node_row[3]  # discord_id from JOIN
                                }
                        except ValueError:
                            await interaction.followup.send(f"Invalid node identifier: {node_identifier}. Use a decimal node number or hex ID with ! prefix.", ephemeral=True)
                            return
            except Exception as e:
                await interaction.followup.send(f"Node identifier invalid or missing from command.")
            
            if found_node:
                # Check if node is already claimed
                if node_data.get("owner_id"):
                    if node_data["owner_id"] == interaction.user.id:
                        await interaction.followup.send("You have already claimed this node!", ephemeral=True)
                    else:
                        await interaction.followup.send(f"This node is already claimed by <@{node_data['owner_id']}>. Contact an admin if this is incorrect.", ephemeral=True)
                    return
                
                # Generate a claim code
                claim_code = await self.generate_claim_code(node_num, interaction.user.id)
                
                # Send the claim instructions via DM
                try:
                    embed = discord.Embed(
                        title="Node Claim Instructions",
                        description=(
                            f"To claim node {node_data.get('longName', 'Unknown')} ({node_data.get('nodeId', 'Unknown')}), "
                            "please follow these steps:"
                        ),
                        color=discord.Color.blue()
                    )
                    
                    embed.add_field(
                        name="Step 1",
                        value="Send the following code as a text message from your Meshtastic device:",
                        inline=False
                    )
                    
                    embed.add_field(
                        name="Claim Code",
                        value=f"```\n{claim_code}\n```",
                        inline=False
                    )
                    
                    embed.add_field(
                        name="Step 2",
                        value="Wait for confirmation. This code will expire in 30 minutes.",
                        inline=False
                    )
                    
                    await interaction.user.send(embed=embed)
                    await interaction.followup.send(f"Check your DMs for instructions on how to claim node {node_data.get('nodeId', 'Unknown')}!", ephemeral=True)
                    
                except discord.Forbidden:
                    await interaction.followup.send("I couldn't send you a DM! Please enable DMs from server members and try again.", ephemeral=True)
            else:
                await interaction.followup.send(f"Node not found: {node_identifier}. Make sure the node has been seen by the system recently.", ephemeral=True)

        except Exception as e:
            await interaction.followup.send(f"Error claiming node: {str(e)}", ephemeral=True)

    async def list_owned_nodes(self, interation: discord.Interaction, user: discord.Member = None):
        """List nodes owned by you or a specified user"""
        
        user = user or interation.user
        user_id = user.id
        
        try:
            with self.get_db() as conn:
                c = conn.cursor()

                # Get nodes owned by the user
                c.execute("""
                    SELECT n.* 
                    FROM nodes n
                    JOIN node_owners o ON n.node_id = o.node_id
                    WHERE o.discord_id = ?
                """, (user_id,))

                owned_nodes = c.fetchall()
            
            if owned_nodes:
                embed = discord.Embed(
                    title=f"Nodes owned by {user.display_name}",
                    color=discord.Color.blue(),
                    timestamp=datetime.now()
                )
                
                for node in owned_nodes:
                    node_data = {
                        "node_id": node[0],
                        "node_num": node[1],
                        "node_id_hex": node[2],
                        "short_name": node[3],
                        "long_name": node[4],
                        "last_seen": node[8]  # Position 8 accounting for public_key at position 7
                    }
                    
                    node_info = (
                        f"**Node ID:** {node_data.get('node_id_hex', 'Unknown')}\n"
                        f"**Name:** {node_data.get('long_name', 'Unknown')}\n"
                    )
                    
                    if node_data.get("last_seen"):
                        last_seen_str = self.format_time_ago(node_data["last_seen"])
                        node_info += f"**Last seen:** {last_seen_str}\n"
                    
                    embed.add_field(
                        name=node_data.get('short_name', 'Unknown'),
                        value=node_info,
                        inline=True
                    )
                
                await interation.followup.send(embed=embed, ephemeral=False)
            else:
                if user == interation.user:
                    await interation.followup.send("You don't own any nodes yet. Use `!node claim` to claim your nodes.", ephemeral=True)
                else:
                    await interation.followup.send(f"{user.display_name} doesn't own any nodes.", ephemeral=True)
                
        except Exception as e:
            await interation.followup.send(f"Error listing nodes: {str(e)}", ephemeral=True)

    async def node_id_lookup(self, interaction: discord.Interaction, node_identifier: str):
        """Look up a node by its NodeNum (decimal) or NodeID (hex with ! prefix)"""
        try:
            conn = sqlite3.connect(self.db_path, timeout=30.0) # Temporary until I can rework this and make it run under Context Manager
            conn.execute("PRAGMA busy_timeout = 30000")
            conn.execute("PRAGMA journal_mode=WAL")
            c = conn.cursor()

            settings = await self.config.all()
            
            found_node_data = None
            
            # Check if we're looking for a node ID (hex with ! prefix)
            if node_identifier.startswith('!'):
                hex_id = node_identifier[1:].lower()  # Remove ! and convert to lowercase
                # Search through nodes to find matching nodeId
                c.execute("""
                    SELECT n.*, o.discord_id, o.discord_username, o.claimed_at 
                    FROM nodes n 
                    LEFT JOIN node_owners o ON n.node_id = o.node_id 
                    WHERE lower(n.node_id_hex) = ?
                """, (f"!{hex_id}",))
                node_row = c.fetchone()
            else:
                # Assume it's a node number (decimal)
                try:
                    node_num = int(node_identifier)
                    c.execute("""
                        SELECT n.*, o.discord_id, o.discord_username, o.claimed_at 
                        FROM nodes n 
                        LEFT JOIN node_owners o ON n.node_id = o.node_id 
                        WHERE n.node_num = ?
                    """, (node_num,))
                    node_row = c.fetchone()
                except ValueError:
                    await interaction.followup.send(f"Invalid node identifier: {node_identifier}. Use a decimal node number or hex ID with ! prefix.", ephemeral=True)
                    conn.close()
                    return
            
            if node_row:
                # Create a structured representation of the node data
                found_node_data = {
                    "node_id": node_row[0],
                    "node_num": node_row[1],
                    "node_id_hex": node_row[2],
                    "short_name": node_row[3],
                    "long_name": node_row[4],
                    "hw_model": node_row[5],
                    "role": node_row[6],
                    "last_seen": node_row[8]  # Position 8 accounting for public_key at position 7
                }
                
                # Add owner information if present
                owner_discord_id = node_row[10]  # From the JOIN with node_owners
                if owner_discord_id:
                    found_node_data["owner"] = {
                        "discord_id": owner_discord_id,
                        "discord_username": node_row[11],
                        "claimed_at": node_row[12]
                    }
                
                # Get latest telemetry
                c.execute("""
                    SELECT battery_level, voltage, temperature, humidity, pressure, timestamp, uptime_seconds
                    FROM node_telemetry 
                    WHERE node_id = ? 
                    ORDER BY timestamp DESC LIMIT 1
                """, (found_node_data["node_id"],))
                telemetry = c.fetchone()
                
                if telemetry:
                    found_node_data["telemetry"] = {
                        "battery_level": telemetry[0],
                        "voltage": telemetry[1],
                        "temperature": telemetry[2],
                        "humidity": telemetry[3],
                        "pressure": telemetry[4],
                        "timestamp": telemetry[5],
                        "uptime_seconds": telemetry[6]
                    }

                # Get latest position
                c.execute("""
                    SELECT latitude, longitude, altitude, timestamp
                    FROM node_positions
                    WHERE node_id = ?
                """, (found_node_data["node_id"],))
                position = c.fetchone()

                if position:
                    found_node_data["position"] = {
                        "latitude": position[0],
                        "longitude": position[1],
                        "altitude": position[2],
                        "timestamp": position[3]
                    }
                
                conn.close()
                
                # Create an embed with the node information
                embed = discord.Embed(
                    title=f"Node Information for:\n{found_node_data.get('long_name', 'Unknown')} ({found_node_data.get('node_id_hex', 'Unknown')})",
                    color=discord.Color.blue(),
                    timestamp=datetime.now()
                )

                if "owner" in found_node_data and found_node_data["owner"]:
                    embed.add_field(
                        name="Owner", 
                        value=f"<@{found_node_data['owner']['discord_id']}>", 
                        inline=False
                    )
                
                # Basic node information
                embed.add_field(name="Node Number", value=found_node_data.get("node_num", "Unknown"), inline=True)
                embed.add_field(name="Node ID", value=found_node_data.get("node_id_hex", "Unknown"), inline=True)
                embed.add_field(name="Short Name", value=found_node_data.get("short_name", "Unknown"), inline=True)
                
                # Add hardware and role info if available
                if found_node_data.get("hw_model"):
                    embed.add_field(name="Hardware", value=found_node_data["hw_model"], inline=True)
                if found_node_data.get("role"):
                    embed.add_field(name="Role", value=found_node_data["role"], inline=True)
                
                # Add last seen
                if found_node_data.get("last_seen"):
                    last_seen_str = self.format_time_ago(found_node_data["last_seen"])
                    embed.add_field(name="Last Seen", value=last_seen_str, inline=True)
                
                # Add telemetry data if available
                if "telemetry" in found_node_data:
                    telemetry = found_node_data["telemetry"]
                    telemetry_text = ""
                    
                    if telemetry.get("battery_level") is not None:
                        telemetry_text += f"Battery: {telemetry['battery_level']}%\n"
                    if telemetry.get("voltage") is not None:
                        telemetry_text += f"Voltage: {telemetry['voltage']:.2f}v\n"
                    if telemetry.get("temperature") is not None:
                        telemetry_text += f"Temperature: {telemetry['temperature']:.1f}°C\n"
                    if telemetry.get("humidity") is not None:
                        telemetry_text += f"Humidity: {telemetry['humidity']:.2f}%\n"
                    if telemetry.get("pressure") is not None:
                        telemetry_text += f"Pressure: {telemetry['pressure']:.2f}hPa\n"
                    if telemetry.get("uptime_seconds") is not None:
                        telemetry_text += f"Uptime: {self.format_uptime(telemetry['uptime_seconds'])}\n"
                    if telemetry.get("timestamp") is not None:
                        telemetry_text += f"Last Updated: {self.format_time_ago(telemetry['timestamp'])}\n"
                        
                    if telemetry_text:
                        embed.add_field(name=f"Telemetry", value=telemetry_text, inline=False)

                if "position" in found_node_data:
                    position = found_node_data["position"]
                    position_text = ""

                    if position.get("latitude"):
                        position_text += f"Latitude: {position['latitude']}\n"
                    if position.get("longitude"):
                        position_text += f"Longitude: {position['longitude']}\n"
                    if position.get("altitude"):
                        position_text += f"Altitude: {position['altitude']}\n"
                    if position.get("timestamp"):
                        position_text += f"Last Updated: {self.format_time_ago(position['timestamp'])}\n"

                    if position_text:
                        embed.add_field(name="Position", value=position_text, inline=False)
                
                # Add MeshView link
                node_num = found_node_data.get('node_num', '')
                embed.add_field(
                    name="Links", 
                    value=(
                        f"[View on MeshView]({settings['meshview_domain']}/packet_list/{node_num})\n"
                        f"[View on Map]({settings['map_domain']}/?node_id={node_num})\n"
                        f"[View Metrics]({settings['metrics_domain']}/d/edqo1uh0eglq8g/node-dashboard?orgId=1&var-nodeID={node_num})"
                    ), 
                    inline=False
                )
                
                await interaction.followup.send(embed=embed, ephemeral=False)
            else:
                await interaction.followup.send(f"Node not found: {node_identifier}", ephemeral=True)
                conn.close()
                
        except Exception as e:
            await interaction.followup.send(f"Error looking up node: {str(e)}", ephemeral=True)

    async def node_stats(self, interaction: discord.Interaction):
        """Show statistics about nodes in the network"""
        try:
            with self.get_db() as conn:
                c = conn.cursor()

                # Get total number of nodes
                c.execute("SELECT COUNT(*) FROM nodes")
                total_nodes = c.fetchone()[0]

                # Get recently active nodes (last 24 hours)
                yesterday = (datetime.now() - timedelta(days=1)).isoformat()
                c.execute("SELECT COUNT(*) FROM nodes WHERE last_seen > ?", (yesterday,))
                active_nodes = c.fetchone()[0]

                # Get claimed node count
                c.execute("SELECT COUNT(*) FROM node_owners")
                claimed_nodes = c.fetchone()[0]

                # Get most common hardware
                c.execute("""
                    SELECT hw_model, COUNT(*) as count 
                    FROM nodes 
                    WHERE hw_model IS NOT NULL AND hw_model != '' 
                    GROUP BY hw_model 
                    ORDER BY count DESC 
                    LIMIT 3
                """)
                top_hw = c.fetchall()

                # Get node roles
                c.execute("""
                    SELECT role, COUNT(*) as count 
                    FROM nodes 
                    WHERE role IS NOT NULL AND role != '' 
                    GROUP BY role 
                    ORDER BY count DESC
                """)
                roles = c.fetchall()

            # Create an embed with the statistics
            embed = discord.Embed(
                title="Meshtastic Node Statistics",
                color=discord.Color.blue(),
                timestamp=datetime.now()
            )

            # Add basic stats
            embed.add_field(name="Total Nodes", value=str(total_nodes), inline=True)
            embed.add_field(name="Active Nodes (24h)", value=str(active_nodes), inline=True)
            embed.add_field(name="Claimed Nodes", value=str(claimed_nodes), inline=True)

            # Add hardware stats if available
            if top_hw:
                hw_text = "\n".join([f"{hw}: {count}" for hw, count in top_hw])
                embed.add_field(name="Top Hardware", value=hw_text, inline=True)

            # Add role stats if available
            if roles:
                role_text = "\n".join([f"{role}: {count}" for role, count in roles])
                embed.add_field(name="Node Roles", value=role_text, inline=True)

            await interaction.followup.send(embed=embed)

        except Exception as e:
            await interaction.followup.send(f"Error generating node statistics: {str(e)}")

    async def toggle_node_notifications(self, interaction: discord.Interaction, node_identifier: str):
        """Toggle notifications for a node owned by the user"""
        if not node_identifier:
            await interaction.followup.send("You must specify a node identifier to toggle notifications.", ephemeral=True)
            return
            
        try:
            with self.get_db() as conn:
                c = conn.cursor()

                node_id = None
                node_info = {}

                # Check if we're looking for a node ID (hex with ! prefix)
                if node_identifier.startswith('!'):
                    hex_id = node_identifier[1:].lower()  # Remove ! and convert to lowercase
                    # Search through nodes to find matching nodeId
                    c.execute("""
                        SELECT n.node_id, n.node_id_hex, n.long_name, o.discord_id, o.notifications
                        FROM nodes n 
                        LEFT JOIN node_owners o ON n.node_id = o.node_id 
                        WHERE lower(n.node_id_hex) = ?
                    """, (f"!{hex_id}",))
                    node_row = c.fetchone()
                else:
                    # Assume it's a node number (decimal)
                    try:
                        node_num = int(node_identifier)
                        c.execute("""
                            SELECT n.node_id, n.node_id_hex, n.long_name, o.discord_id, o.notifications
                            FROM nodes n 
                            LEFT JOIN node_owners o ON n.node_id = o.node_id 
                            WHERE n.node_num = ?
                        """, (node_num,))
                        node_row = c.fetchone()
                    except ValueError:
                        await interaction.followup.send(f"Invalid node identifier: {node_identifier}. Use a decimal node number or hex ID with ! prefix.", ephemeral=True)
                        conn.close()
                        return

                # Check if node exists and is owned by the user
                if not node_row:
                    await interaction.followup.send(f"Node not found: {node_identifier}", ephemeral=True)
                    conn.close()
                    return

                node_id, node_id_hex, long_name, owner_id, current_notification_status = node_row

                # Check if the node is owned by the user
                if not owner_id:
                    await interaction.followup.send(f"Node {node_id_hex} is not currently claimed by anyone.", ephemeral=True)
                    conn.close()
                    return

                if int(owner_id) != interaction.user.id:
                    await interaction.followup.send(f"You don't own node {node_id_hex}. It's owned by <@{owner_id}>.", ephemeral=True)
                    conn.close()
                    return

                # Toggle notification status
                new_status = not bool(current_notification_status)

                # Update the database
                c.execute("""
                    UPDATE node_owners 
                    SET notifications = ? 
                    WHERE node_id = ? AND discord_id = ?
                """, (new_status, node_id, owner_id))

                conn.commit()
            
            # Send confirmation
            status_text = "enabled" if new_status else "disabled"
            
            embed = discord.Embed(
                title="Node Notifications Updated",
                description=f"Notifications for node {long_name} ({node_id_hex}) have been {status_text}.",
                color=discord.Color.green() if new_status else discord.Color.red(),
                timestamp=datetime.now()
            )
            
            await interaction.followup.send(embed=embed, ephemeral=True)
            
        except Exception as e:
            await interaction.followup.send(f"Error toggling notifications: {str(e)}", ephemeral=True)

    # Node Administration commands (admin only)
    @commands.group(name="nodeadmin")
    @commands.admin_or_permissions(administrator=True)
    async def node_admin(self, ctx: commands.Context):
        """Node administration commands"""

    @node_admin.command(name="unclaim")
    @commands.admin_or_permissions(administrator=True)
    async def unclaim_node(self, ctx: commands.Context, node_identifier: str):
        """Admin: Remove ownership of a node
        
        Examples:
        [p]node unclaim 0123456789
        [p]node unclaim !12ab34cd
        """
        try:
            with self.get_db() as conn:
                c = conn.cursor()

                node_id = None
                owner_username = None
                node_id_hex = None

                # Check if we're looking for a node ID (hex with ! prefix)
                if node_identifier.startswith('!'):
                    hex_id = node_identifier[1:].lower()  # Remove ! and convert to lowercase
                    # Search for the node to get its node_id
                    c.execute("""
                        SELECT n.node_id, n.node_id_hex, n.long_name, o.discord_id
                        FROM nodes n
                        LEFT JOIN node_owners o ON n.node_id = o.node_id
                        WHERE lower(n.node_id_hex) = ?
                    """, (f"!{hex_id}",))
                    result = c.fetchone()
                    if result:
                        node_id, node_id_hex, long_name, discord_id = result
                else:
                    # Assume it's a node number (decimal)
                    try:
                        node_num = int(node_identifier)
                        # Search for the node to get its node_id
                        c.execute("""
                            SELECT n.node_id, n.node_id_hex, n.long_name, o.discord_id
                            FROM nodes n
                            LEFT JOIN node_owners o ON n.node_id = o.node_id
                            WHERE n.node_num = ?
                        """, (node_num,))
                        result = c.fetchone()
                        if result:
                            node_id, node_id_hex, long_name, discord_id = result
                    except ValueError:
                        await ctx.send(f"Invalid node identifier: {node_identifier}. Use a decimal node number or hex ID with ! prefix.")
                        conn.close()
                        return

                if node_id:
                    # Check if node is claimed
                    if discord_id:
                        # Remove the owner
                        c.execute("DELETE FROM node_owners WHERE node_id = ?", (node_id,))
                        conn.commit()

                        await ctx.send(f"Node {long_name} ({node_id_hex}) is no longer claimed by <@{discord_id}>.")
                    else:
                        await ctx.send(f"Node {long_name} ({node_id_hex}) is not currently claimed by anyone.")
                else:
                    await ctx.send(f"Node not found: {node_identifier}.")
                
        except Exception as e:
            await ctx.send(f"Error unclaiming node: {str(e)}")

    @node_admin.command(name="setowner")
    @commands.admin_or_permissions(administrator=True)
    async def set_node_owner(self, ctx: commands.Context, node_identifier: str, user: discord.Member):
        """Admin: Manually set a node's owner
    
        Examples:
        [p]node setowner 0123456789 @username
        [p]node setowner !12ab34cd @username
        """
        try:
            with self.get_db() as conn:
                c = conn.cursor()

                node_id = None
                node_id_hex = None
                previous_owner_id = None

                # Check if we're looking for a node ID (hex with ! prefix)
                if node_identifier.startswith('!'):
                    hex_id = node_identifier[1:].lower()  # Remove ! and convert to lowercase
                    # Search for the node to get its node_id
                    c.execute("""
                        SELECT n.node_id, n.node_id_hex, n.long_name, o.discord_id 
                        FROM nodes n
                        LEFT JOIN node_owners o ON n.node_id = o.node_id
                        WHERE lower(n.node_id_hex) = ?
                    """, (f"!{hex_id}",))
                    result = c.fetchone()
                    if result:
                        node_id, node_id_hex, long_name, previous_owner_id = result
                else:
                    # Assume it's a node number (decimal)
                    try:
                        node_num = int(node_identifier)
                        # Search for the node to get its node_id
                        c.execute("""
                            SELECT n.node_id, n.node_id_hex, n.long_name, o.discord_id 
                            FROM nodes n
                            LEFT JOIN node_owners o ON n.node_id = o.node_id
                            WHERE n.node_num = ?
                        """, (node_num,))
                        result = c.fetchone()
                        if result:
                            node_id, node_id_hex, long_name, previous_owner_id = result
                    except ValueError:
                        await ctx.send(f"Invalid node identifier: {node_identifier}. Use a decimal node number or hex ID with ! prefix.")
                        return
            
            if node_id:
                # Check if node is already claimed
                if previous_owner_id:
                    await ctx.send(f"This node was previously claimed by <@{previous_owner_id}>. Transferring ownership...")
            
                # Set new owner
                success = await self.register_node_owner(
                    node_id, 
                    user.id,
                    str(user)
                )
            
                if success:
                    await ctx.send(f"✅ Node {long_name} ({node_id_hex}) is now owned by {user.mention}")
                    
                    # Notify the new owner via DM
                    try:
                        embed = discord.Embed(
                            title="Node Assigned",
                            description=f"An administrator has assigned node {long_name} ({node_id_hex}) to you.",
                            color=discord.Color.green()
                        )

                        if user.id == self.bot.user.id:
                            return
                        else:
                            await user.send(embed=embed)
                            
                    except discord.Forbidden:
                        await ctx.send("Note: I couldn't notify the user via DM as they have DMs disabled.")
                else:
                    await ctx.send(f"❌ Failed to set owner for node {node_identifier}.")
            else:
                await ctx.send(f"Node not found: {node_identifier}.")
            
        except Exception as e:
            await ctx.send(f"Error setting node owner: {str(e)}")

    @node_admin.command(name="mute")
    @commands.admin_or_permissions(administrator=True)
    async def mute_node(self, ctx: commands.Context, node_identifier: str, 
                        mute_type: str = "both", reason: str = "No reason provided"):
        """Mute a node from sending traceroutes or messages to Discord

        mute_type options:
        - traceroute: Mute only traceroute messages
        - messages: Mute only text messages
        - both: Mute both traceroute and text messages (default)

        Examples:
        [p]nodeadmin mute 0123456789 traceroute Spamming traceroutes
        [p]nodeadmin mute !12ab34cd messages Inappropriate content
        [p]nodeadmin mute 0123456789 both Testing mute functionality
        """
        try:
            with self.get_db() as conn:
                c = conn.cursor()

                node_id = None
                node_id_hex = None
                node_num = None
                long_name = None

                # Check if we're looking for a node ID (hex with ! prefix)
                if node_identifier.startswith('!'):
                    hex_id = node_identifier[1:].lower()  # Remove ! and convert to lowercase
                    # Search for the node to get its node_id
                    c.execute("""
                        SELECT node_id, node_id_hex, node_num, long_name 
                        FROM nodes
                        WHERE lower(node_id_hex) = ?
                    """, (f"!{hex_id}",))
                    result = c.fetchone()
                    if result:
                        node_id, node_id_hex, node_num, long_name = result
                else:
                    # Assume it's a node number (decimal)
                    try:
                        node_num = int(node_identifier)
                        # Search for the node to get its node_id
                        c.execute("""
                            SELECT node_id, node_id_hex, node_num, long_name 
                            FROM nodes
                            WHERE node_num = ?
                        """, (node_num,))
                        result = c.fetchone()
                        if result:
                            node_id, node_id_hex, node_num, long_name = result
                    except ValueError:
                        await ctx.send(f"Invalid node identifier: {node_identifier}. Use a decimal node number or hex ID with ! prefix.")
                        return

                if not node_id:
                    await ctx.send(f"Node not found: {node_identifier}")
                    return

                # Determine which types to mute
                mute_traceroute = 0
                mute_messages = 0

                mute_type = mute_type.lower()
                if mute_type == "traceroute":
                    mute_traceroute = 1
                elif mute_type == "messages":
                    mute_messages = 1
                elif mute_type == "both":
                    mute_traceroute = 1
                    mute_messages = 1
                else:
                    await ctx.send("Invalid mute type. Use 'traceroute', 'messages', or 'both'.")
                    return

                # Check if node is already muted
                c.execute("SELECT mute_traceroute, mute_messages FROM muted_nodes WHERE node_id = ?", (node_id,))
                existing = c.fetchone()

                current_time = datetime.now().isoformat()
                muter_id = str(ctx.author.id)

                if existing:
                    # Update existing mute
                    c.execute("""
                        UPDATE muted_nodes 
                        SET mute_traceroute = ?, mute_messages = ?, muted_by = ?, muted_at = ?, reason = ?
                        WHERE node_id = ?
                    """, (mute_traceroute, mute_messages, muter_id, current_time, reason, node_id))
                else:
                    # Create new mute
                    c.execute("""
                        INSERT INTO muted_nodes 
                        (node_id, mute_traceroute, mute_messages, muted_by, muted_at, reason)
                        VALUES (?, ?, ?, ?, ?, ?)
                    """, (node_id, mute_traceroute, mute_messages, muter_id, current_time, reason))

                conn.commit()

            # Create response message
            muted_types = []
            if mute_traceroute:
                muted_types.append("traceroute messages")
            if mute_messages:
                muted_types.append("text messages")

            muted_types_str = " and ".join(muted_types)

            embed = discord.Embed(
                title="Node Muted",
                description=f"Node {long_name} ({node_id_hex}) has been muted from sending {muted_types_str} to Discord.",
                color=discord.Color.red(),
                timestamp=datetime.now()
            )

            embed.add_field(name="Node Number", value=str(node_num), inline=True)
            embed.add_field(name="Reason", value=reason, inline=True)
            embed.add_field(name="Muted By", value=f"<@{muter_id}>", inline=True)

            await ctx.send(embed=embed)

        except Exception as e:
            await ctx.send(f"Error muting node: {str(e)}")

    @node_admin.command(name="unmute")
    @commands.admin_or_permissions(administrator=True)
    async def unmute_node(self, ctx: commands.Context, node_identifier: str):
        """Remove muting from a node

        Examples:
        [p]nodeadmin unmute 0123456789
        [p]nodeadmin unmute !12ab34cd
        """
        try:
            with self.get_db() as conn:
                c = conn.cursor()

                node_id = None
                node_id_hex = None
                node_num = None
                long_name = None

                # Check if we're looking for a node ID (hex with ! prefix)
                if node_identifier.startswith('!'):
                    hex_id = node_identifier[1:].lower()
                    c.execute("""
                        SELECT node_id, node_id_hex, node_num, long_name 
                        FROM nodes
                        WHERE lower(node_id_hex) = ?
                    """, (f"!{hex_id}",))
                    result = c.fetchone()
                    if result:
                        node_id, node_id_hex, node_num, long_name = result
                else:
                    # Assume it's a node number (decimal)
                    try:
                        node_num = int(node_identifier)
                        c.execute("""
                            SELECT node_id, node_id_hex, node_num, long_name 
                            FROM nodes
                            WHERE node_num = ?
                        """, (node_num,))
                        result = c.fetchone()
                        if result:
                            node_id, node_id_hex, node_num, long_name = result
                    except ValueError:
                        await ctx.send(f"Invalid node identifier: {node_identifier}")
                        return

                if not node_id:
                    await ctx.send(f"Node not found: {node_identifier}")
                    return

                # Check if node is muted
                c.execute("SELECT mute_traceroute, mute_messages FROM muted_nodes WHERE node_id = ?", (node_id,))
                existing = c.fetchone()

                if existing:
                    c.execute("DELETE FROM muted_nodes WHERE node_id = ?", (node_id,))
                    conn.commit()

                    embed = discord.Embed(
                        title="Node Unmuted",
                        description=f"Node {long_name} ({node_id_hex}) has been unmuted.",
                        color=discord.Color.green(),
                        timestamp=datetime.now()
                    )

                    embed.add_field(name="Node Number", value=str(node_num), inline=True)
                    embed.add_field(name="Unmuted By", value=f"<@{str(ctx.author.id)}>", inline=True)

                    await ctx.send(embed=embed)
                else:
                    await ctx.send(f"Node {node_id_hex or node_identifier} is not currently muted.")

        except Exception as e:
            await ctx.send(f"Error unmuting node: {str(e)}")

    @node_admin.command(name="listmuted")
    async def list_muted_nodes(self, ctx: commands.Context):
        """List all currently muted nodes"""
        try:
            with self.get_db() as conn:
                c = conn.cursor()

                c.execute("""
                    SELECT m.node_id, m.mute_traceroute, m.mute_messages, 
                           m.muted_by, m.muted_at, m.reason,
                           n.node_id_hex, n.long_name, n.node_num
                    FROM muted_nodes m
                    JOIN nodes n ON m.node_id = n.node_id
                    ORDER BY m.muted_at DESC
                """)

                muted_nodes = c.fetchall()

            if not muted_nodes:
                await ctx.send("No nodes are currently muted.")
                return

            embed = discord.Embed(
                title="Muted Nodes",
                color=discord.Color.red(),
                timestamp=datetime.now()
            )

            for node in muted_nodes:
                node_id, mute_traceroute, mute_messages, muted_by, muted_at, reason, node_id_hex, long_name, node_num = node

                muted_types = []
                if mute_traceroute:
                    muted_types.append("Traceroutes")
                if mute_messages:
                    muted_types.append("Messages")

                muted_types_str = " & ".join(muted_types)

                # Format the muted time
                muted_time_str = self.format_time_ago(muted_at)

                field_name = f"{long_name} ({node_id_hex})"
                field_value = (
                    f"**Node #:** {node_num}\n"
                    f"**Muted:** {muted_types_str}\n"
                    f"**By:** <@{muted_by}>\n"
                    f"**When:** {muted_time_str}\n"
                    f"**Reason:** {reason}"
                )

                embed.add_field(name=field_name, value=field_value, inline=True)

            await ctx.send(embed=embed)

        except Exception as e:
            await ctx.send(f"Error listing muted nodes: {str(e)}")

    @node_admin.command(name="roles")
    @commands.admin_or_permissions(administrator=True)
    async def nodes_by_role(self, ctx: commands.Context, role: str = None):
        """List nodes grouped by role or nodes with a specific role
    
        If no role is specified, shows all roles with their nodes.
        """
        try:
            with self.get_db() as conn:
                c = conn.cursor()

                if role:
                    # If a specific role was requested, get nodes with that role
                    c.execute("""
                        SELECT node_id_hex, long_name, short_name, last_seen, channel
                        FROM nodes
                        WHERE LOWER(role) = LOWER(?)
                        ORDER BY long_name
                    """, (role,))

                    nodes = c.fetchall()

                    if not nodes:
                        await ctx.send(f"No nodes found with role '{role}'.")
                        return

                    # Create pages for this specific role
                    title = f"Nodes with Role: {role}"
                    pages = self.create_node_pages(nodes, title)

                else:
                    # Get all roles and their counts
                    c.execute("""
                        SELECT role, COUNT(*) as count 
                        FROM nodes 
                        WHERE role IS NOT NULL AND role != ''
                        GROUP BY role 
                        ORDER BY count DESC
                    """)

                    roles = c.fetchall()

                    if not roles:
                        await ctx.send("No roles found in the database.")
                        return

                    pages = []

                    # Create a page for each role
                    for role_name, count in roles:
                        # Get nodes with this role
                        c.execute("""
                            SELECT node_id_hex, long_name, short_name, last_seen, channel
                            FROM nodes
                            WHERE role = ?
                            ORDER BY long_name
                        """, (role_name,))

                        nodes = c.fetchall()

                        if nodes:
                            title = f"Nodes with Role: {role_name} ({count})"
                            role_pages = self.create_node_pages(nodes, title)
                            pages.extend(role_pages)
            
            # Display the paged menu using the standard Red menu system
            if pages:
                await menu(ctx, pages, DEFAULT_CONTROLS)
            else:
                await ctx.send("No nodes found.")
    
        except Exception as e:
            await ctx.send(f"Error listing nodes by role: {str(e)}")