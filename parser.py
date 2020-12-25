from quarry.types.nbt import TagRoot
from struct import pack
from cipher import Cipher
from utils import *
import base64
import os
import config

from quarry.types.nbt import TagRoot
from quarry.types.chunk import BlockArray
from quarry.types.registry import OpaqueRegistry

import zlib

state = 0
compress = 0

c_cipher = Cipher()
s_cipher = Cipher()

shared_secret_hex = ""


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
    if config.WORLD_DOWNLOADER:
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
    return f"PLAY spawn_xp {eid} {x} {y} {z} {count}"


def s_play_chunk_data(packet):
    or_packet = packet
    chunk_x, packet = decode_int(packet)
    chunk_z, packet = decode_int(packet)
    with open(os.path.join(config.BASE_DIR, shared_secret_hex, f"{chunk_x}.{chunk_z}.chunk_packet"), "wb") as f:
        f.write(or_packet)
    # full_chunk, packet = decode_boolean(packet)
    # primary_bitmask, packet = decode_varint(packet)
    # heightmaps = TagRoot.from_bytes(packet)
    # heightmaps_len = len(heightmaps.to_bytes())
    # packet = packet[heightmaps_len:]
    # if full_chunk:
    #     biomes_length, packet = decode_varint(packet)
    #     biomes = []
    #     for i in range(biomes_length):
    #         b, packet = decode_varint(packet)
    #         biomes.append(b)
    # size, packet = decode_varint(packet)
    # data, packet = packet[:size], packet[size:]

    # chunk_data = parse_chunk_packet_data(data) num_block_entities, packet = decode_varint(packet) entities = [] for
    # i in range(num_block_entities): entity = TagRoot.from_bytes(packet) entity_len = len(entity.to_bytes()) packet
    # = packet[entity_len:] entities.append(entity) return f"PLAY chunk_data {chunk_x} {chunk_z} {full_chunk} {
    # primary_bitmask} {heightmaps} {biomes_length} BIOMES {size} DATA {num_block_entities} {entities}"


def s_play_light_data(packet):
    or_packet = packet
    chunk_x, packet = decode_varint(packet)
    chunk_z, packet = decode_varint(packet)
    with open(os.path.join(config.BASE_DIR, shared_secret_hex, f"{chunk_x}.{chunk_z}.light_packet"), "wb") as f:
        f.write(or_packet)


def s_play_resource_pack(packet):
    url, packet = decode_string(packet)
    _hash, _packet = decode_string(packet)
    with open(os.path.join(config.BASE_DIR, shared_secret_hex, f"resource_pack_link.url"), "w") as f:
        f.write(url)


# ----------- OTHER STUFF -----------

def parse_chunk_packet_data(data):
    block_count, data = decode_short(data)
    bits_per_block, data = decode_unsigned_byte(data)

    palette, data = None, data
    _data_array_length, _data = decode_varint(data)
    # chunk_data = BlockArray.from_bytes(data[:data_array_length], \
    # bits_per_block, OpaqueRegistry(14), palette, block_count)
    # for i in range(data_array_length):
    # d, data = decode_long(data)
    # data_arr.append(d)


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
            0x20: s_play_chunk_data,
            0x23: s_play_light_data,
            0x24: s_play_join_game,
            0x38: s_play_resource_pack,
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
            0x05: c_play_settings
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
