from functools import singledispatch
from struct import pack
from cipher import Cipher
from utils import *
import base64
import os
import config

from quarry.types.nbt import TagRoot
import zlib

state = 0
compress = 0

c_cipher = Cipher()
s_cipher = Cipher()

shared_secret_hex = ""


statistic_catagories = ["mined", "crafted", "used", "broken", "picked_up", "dropped", "killed", "killed_by", "costum"]

# ---------- HANDSHAKE ----------------

def c_handshake(packet):
    protocol_version, packet = decode_varint(packet)
    ip, packet = decode_string(packet)
    port, packet = decode_unsigned_short(packet)
    next_state, packet = decode_varint(packet)
    set_state(next_state)
    return f"HANDSHAKE {ip}:{port} / {protocol_version} / {next_state}"


# ------------- STATUS ------------------

def c_status_request(_packet):
    return f"STATUS req"


def c_status_ping(packet):
    return f"STATUS ping {decode_long(packet)[0]}"


def s_status_resp(packet):
    resp_string, packet = decode_string(packet)
    return f"STATUS res {resp_string}"


def s_status_pong(packet):
    set_state(0)
    return f"STATUS pong {decode_long(packet)[0]}"


# ----------- LOGIN ------------

def c_login_start(packet):
    username, packet = decode_string(packet)
    return f"LOGIN start username: {username}"


def c_login_enc_res(packet):
    shared_secret_length, packet = decode_varint(packet)
    shared_secret, packet = packet[:shared_secret_length], packet[shared_secret_length:]
    verify_token_length, packet = decode_varint(packet)
    verify_token = packet[:verify_token_length]
    if os.name == "nt":
        with open(os.path.join(os.environ["APPDATA"] ,".minecraft/logs/latest.log"), "r") as logfile:
            log_lines = logfile.readlines()
    else:
        with open("/home/zegevlier/.minecraft/logs/latest.log", "r") as logfile:
            log_lines = logfile.readlines()
    actual_shared_secret = ""
    for log_line in log_lines:
        if "[STDOUT]: Secret Key: " in log_line:
            actual_shared_secret = base64.b64decode(log_line.split("[STDOUT]: Secret Key: ")[1])
    c_cipher.enable(actual_shared_secret)
    s_cipher.enable(actual_shared_secret)
    global shared_secret_hex
    shared_secret_hex = actual_shared_secret.hex()
    os.mkdir(os.path.join(config.BASE_DIR, shared_secret_hex))

    return f"LOGIN enc res ENCSharedSec: [{shared_secret.hex()}] ENCVerifyToken: [{verify_token.hex()}] " \
           f"ActualSharedSecret: [{actual_shared_secret.hex()}] "


def s_login_enc_req(packet):
    server_id, packet = decode_string(packet)
    public_key_length, packet = decode_varint(packet)
    public_key, packet = packet[:public_key_length], packet[public_key_length:]
    verify_token_length, packet = decode_varint(packet)
    verify_token = packet[:verify_token_length]
    return f"LOGIN enc req ServerId: [{server_id}] PublicKey: [{public_key.hex()}] VerifyToken: [{verify_token.hex()}]"


def s_login_set_compression(packet):
    global compress
    compress, packet = decode_varint(packet)
    return f"LOGIN compress {compress}"


def s_login_success(packet):
    uuid, packet = packet[:16], packet[16:]
    username, packet = decode_string(packet)
    set_state(3)
    return f"LOGIN success {username}"


# ------------- PLAY ----------------

def c_play_settings(packet):
    locale, packet = decode_string(packet)
    view_distance, packet = decode_byte(packet)
    chat_mode, packet = decode_varint(packet)
    chat_colors, packet = decode_boolean(packet)
    displayed_skin_parts, packet = decode_unsigned_byte(packet)
    main_hand, packet = decode_varint(packet)
    return f"PLAY settings {locale} {view_distance} {chat_mode} {chat_colors} " \
           f"0{bin(displayed_skin_parts).replace('0b', '')} {main_hand}"


def c_play_vehicle_move(packet):
    print("MOVED!!")
    x, packet = decode_double(packet)
    y, packet = decode_double(packet)
    z, packet = decode_double(packet)
    yaw, packet = decode_float(packet)
    pitch, packet = decode_float(packet)
    if config.VEHICLE_MOVE:
        return f"PLAY vehicle_move {x} {y} {z} {yaw} {pitch}"


def c_play_player_abilities(packet):
    flags, packet = decode_byte(packet)
    if flags == 0x02:
        flying = True
    else:
        flying = False
    if config.PLAYER_ABILITIES:
        return f"PLAY player_abilities flying: {flying}"


def s_play_join_game(packet):
    player_eid, packet = packet[:4], packet[4:]
    is_hardcore, packet = decode_boolean(packet)
    gamemode, packet = decode_byte(packet)
    return f"PLAY join_game {gamemode}"


def s_play_spawn_xp(packet):
    eid, packet = decode_varint(packet)
    x, packet = decode_double(packet)
    y, packet = decode_double(packet)
    z, packet = decode_double(packet)
    count, packet = decode_short(packet)
    if config.SPAWN_XP:
        return f"PLAY spawn_xp {eid} {x} {y} {z} {count}"


def s_play_chunk_data(packet):
    if config.WORLD_DOWNLOADER:
        or_packet = packet
        chunk_x, packet = decode_int(packet)
        chunk_z, packet = decode_int(packet)
        with open(os.path.join(config.BASE_DIR, shared_secret_hex, f"{chunk_x}.{chunk_z}.chunk_packet"), "wb") as f:
            f.write(or_packet)


def s_play_light_data(packet):
    if config.WORLD_DOWNLOADER:
        or_packet = packet
        chunk_x, packet = decode_varint(packet)
        chunk_z, packet = decode_varint(packet)
        with open(os.path.join(config.BASE_DIR, shared_secret_hex, f"{chunk_x}.{chunk_z}.light_packet"), "wb") as f:
            f.write(or_packet)


def s_play_resource_pack(packet):
    url, packet = decode_string(packet)
    hash, _packet = decode_string(packet)
    with open(os.path.join(config.BASE_DIR, shared_secret_hex, f"resource_pack_link.url"), "w") as f:
        f.write(url)
    return f"PLAY resource_pack {url} {hash}"


def s_play_disconnect(packet):
    set_state(0)
    global compress
    compress = 0
    c_cipher.disable()
    s_cipher.disable()
    reason, packet = decode_chat(packet)
    return f"PLAY disconnect {reason}"


def s_play_block_entity_data(packet):
    position, packet = packet[:8], packet[8:]
    action, packet = decode_unsigned_byte(packet)
    nbt_data = TagRoot.from_bytes(packet)
    if config.BLOCK_ENTITY_UPDATES:
        return f"PLAY block_entity_update {action} {nbt_data}"


def s_play_nbt_query_resp(packet):
    print("activated")
    transaction_id, packet = decode_varint(packet)
    nbt_data = TagRoot.from_bytes(packet)
    if config.NBT_QUERY_RESP:
        return f"PLAY nbt_query_resp {transaction_id} {nbt_data}"


def s_play_tab_complete(packet):
    pid, packet = decode_varint(packet)
    start, packet = decode_varint(packet)
    length, packet = decode_varint(packet)
    count, packet = decode_varint(packet)
    matches = []
    for i in range(count):
        match, packet = decode_string(packet)
        has_tooltip, packet = decode_boolean(packet)
        if not has_tooltip:
            tooltip, packet = decode_chat(packet)
        matches.append(match)
    if config.TAB_COMPLETE:
        return f"PLAY tab_complete {pid} {start} {length} {matches}"


def s_play_player_info(packet):
    action, packet = decode_varint(packet)
    num_players, packet = decode_varint(packet)
    players = []
    for i in range(num_players):
        uuid, packet = decode_uuid(packet)
        if action == 0:
            name, packet = decode_string(packet)
            num_properties, packet = decode_varint(packet)
            properties = {}
            for j in range(num_properties):
                property_name, packet = decode_string(packet)
                property_value, packet = decode_string(packet)
                properties[property_name] = property_value
                is_signed, packet = decode_boolean(packet)
                if is_signed:
                    signature, packet = decode_string(packet)
            gamemode, packet = decode_varint(packet)
            ping, packet = decode_varint(packet)
            has_display_name, packet = decode_boolean(packet)
            display_name = None
            if has_display_name:
                display_name, packet = decode_chat(packet)
            players.append(f"{uuid} {name} {properties} {gamemode} {ping} {display_name}")
        elif action == 1:
            gamemode, packet = decode_varint(packet)
            players.append(f"{uuid} {gamemode}")
        elif action == 2:
            ping, packet = decode_varint(packet)
            players.append(f"{uuid} {ping}")
        elif action == 3:
            has_display_name, packet = decode_boolean(packet)
            display_name = None
            if has_display_name:
                display_name, packet = decode_chat(packet)
            players.append(f"{uuid} {display_name}")
        elif action == 4:
            players.append(f"{uuid}")
        

    if config.PLAYER_INFO:
        return f"PLAY player_info {action} {players}"


def s_play_declare_recipes(packet):
    num_recipes, packet = decode_varint(packet)
    recipes = []
    for i in range(num_recipes):
        recipe_type, packet = decode_string(packet)
        if "crafting_shapeless" in recipe_type:
            group, packet = decode_string(packet)
            ingredient_count, packet = decode_varint(packet)

        elif "crafting_shaped" in recipe_type:
            pass
        elif "crafting_special_armordye" in recipe_type:
            pass
        elif "crafting_special_bookcloning" in recipe_type:
            pass
        elif "crafting_special_mapcloning" in recipe_type:
            pass
        elif "crafting_special_mapextending" in recipe_type:
            pass
        elif "crafting_special_firework_rocket" in recipe_type:
            pass
        elif "crafting_special_firework_star" in recipe_type:
            pass
        elif "crafting_special_firework_star_fade" in recipe_type:
            pass
        elif "crafting_special_repairitem" in recipe_type:
            pass
        elif "crafting_special_tippedarrow" in recipe_type:
            pass
        elif "crafting_special_bannerduplicate" in recipe_type:
            pass
        elif "crafting_special_banneraddpattern" in recipe_type:
            pass
        elif "crafting_special_shielddecoration" in recipe_type:
            pass
        elif "crafting_special_shulkerboxcoloring" in recipe_type:
            pass
        elif "smelting" in recipe_type:
            pass
        elif "blasting" in recipe_type:
            pass
        elif "smoking" in recipe_type:
            pass
        elif "campfire_cooking" in recipe_type:
            pass
        elif "stonecutting" in recipe_type:
            pass
        elif "smithing" in recipe_type:
            pass
    if config.DECLARE_RECIPES:
        return f"PLAY declare_recipes {packet}"

def s_play_statistics(packet):
    count, packet = decode_varint(packet)
    stats = []
    for i in range(count):
        catagory_id, packet = decode_varint(packet)
        statstic_id, packet = decode_varint(packet)
        value, packet = decode_varint(packet)
        stats.append(f"{statistic_catagories[catagory_id]} {statstic_id} {value}")
    return f"PLAY stastics {stats}"


# ----------- OTHER STUFF -----------

def set_state(value):
    global state
    state = value
    print(f"Updated state to {value}")


def noop(_packet):
    pass


handlers = {
    "server": [
        {},
        {
            0x00: s_status_resp,
            0x01: s_status_pong
        },
        {
            0x01: s_login_enc_req,
            0x02: s_login_success,
            0x03: s_login_set_compression
        },
        {
            0x01: s_play_spawn_xp,
            0x09: s_play_block_entity_data,
            0x06: s_play_statistics,
            0xF: s_play_tab_complete,
            0x19: s_play_disconnect,
            0x20: s_play_chunk_data,
            0x23: s_play_light_data,
            0x24: s_play_join_game,
            0x32: s_play_player_info,
            0x38: s_play_resource_pack,
            0x54: s_play_nbt_query_resp,
            # 0x5A: s_play_declare_recipes
        }
    ],
    "client": [
        {
            0x00: c_handshake
        },
        {
            0x00: c_status_request,
            0x01: c_status_ping
        },
        {
            0x00: c_login_start,
            0x01: c_login_enc_res
        },
        {
            0x05: c_play_settings,
            0x16: c_play_vehicle_move,
            0x1A: c_play_player_abilities,
        }
    ],
}


def c_parse(client_queue):
    data = b""
    while True:
        new_packet = client_queue.get()
        new_packet = c_cipher.decrypt(new_packet)
        data += new_packet
        while len(data) > 0:
            o_data = data
            try:
                (packet_length, data) = decode_varint(data)
            except Exception:
                break
            if len(data) < packet_length:
                data = o_data
                break
            packet, data = data[:packet_length], data[packet_length:]
            if compress > 0:
                data_length, packet = decode_varint(packet)
                if data_length > 0:
                    try:
                        packet = zlib.decompress(packet)
                    except Exception:
                        print("Could not decompress packet!")
                        continue
                else:
                    pass

            (pid, packet) = decode_varint(packet)
            msg = handlers["client"][state].get(pid, noop)(packet)
            if msg is not None:
                print(f"[client]({state}) {msg}")


def s_parse(server_queue):
    data = b""
    while True:
        new_packet = server_queue.get()
        new_packet = s_cipher.decrypt(new_packet)
        data += new_packet
        while len(data) > 0:
            o_data = data
            try:
                (packet_length, data) = decode_varint(data)
            except Exception:
                break
            if len(data) < packet_length:
                data = o_data
                break
            packet, data = data[:packet_length], data[packet_length:]
            if compress > 0:
                data_length, packet = decode_varint(packet)
                if data_length > 0:
                    try:
                        packet = zlib.decompress(packet)
                    except Exception:
                        print("Could not decompress packet!")
                        continue
                else:
                    pass

            (pid, packet) = decode_varint(packet)
            msg = handlers["server"][state].get(pid, noop)(packet)
            if msg is not None:
                print(f"[server]({state}) {msg}")
