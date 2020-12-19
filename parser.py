from struct import pack
from cipher import Cipher
from utils import *
import base64

import zlib

state = 0
compress = 0

c_cipher = Cipher()
s_cipher = Cipher()


# ---------- HANDSHAKE ----------------

def c_handshake(packet):
    prot_version, packet = decode_varint(packet)
    ip, packet = decode_string(packet)
    port, packet = decode_unsigned_short(packet)
    next_state, packet = decode_varint(packet)
    set_state(next_state)
    return f"HANDSHAKE {ip}:{port} / {prot_version} / {next_state}"

# ------------- STATUS ------------------

def c_status_request(packet):
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

    return f"LOGIN enc res ENCSharedSec: [{shared_secret.hex()}] ENCVerifyToken: [{verify_token.hex()}] ActualSharedSecret: [{actual_shared_secret.hex()}]"

def s_login_enc_req(packet):
    server_id, packet = decode_string(packet)
    public_key_length, packet = decode_varint(packet)
    public_key, packet = packet[:public_key_length], packet[public_key_length:]
    verify_token_length, packet = decode_varint(packet)
    verify_token = packet[:verify_token_length]
    return f"LOGIN enc req ServerId: [{server_id}] PublicKey: [{public_key.hex()}] VerifyToken: [{verify_token.hex()}]"

def s_login_setcompression(packet):
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
    return f"PLAY settings {locale} {view_distance} {chat_mode} {chat_colors} 0{bin(displayed_skin_parts).replace('0b', '')} {main_hand}"

def s_play_joingame(packet):
    player_eid, packet = packet[:4], packet[4:]
    is_hardcore, packet = decode_boolean(packet)
    gamemode, packet = decode_byte(packet)
    return f"PLAY joingame {gamemode}"

def s_play_spawn_xp(packet):
    eid, packet = decode_varint(packet)
    x, packet = decode_double(packet)
    y, packet = decode_double(packet)
    z, packet = decode_double(packet)
    count, packet = decode_short(packet)
    return f"PLAY spawn_xp {eid} {x} {y} {z} {count}"

# ----------- OTHER STUFF -----------

def set_state(value):
    global state
    state = value
    print(f"Updated state to {value}")

def noop(packet):
    # return packet.hex()
    pass

handelers = {
    "server": [
        {}, 
        {
            0x00: s_status_resp,
            0x01: s_status_pong
        }, 
        {
            0x01: s_login_enc_req,
            0x02: s_login_success,
            0x03: s_login_setcompression
        }, 
        {
            0x01: s_play_spawn_xp,
            0x24: s_play_joingame
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
            except:
                break
            if len(data) < packet_length:
                data = o_data
                break
            # print(packet_length)
            packet, data = data[:packet_length], data[packet_length:]
            if compress > 0:
                data_length, packet = decode_varint(packet)
                if data_length > 0:
                    try:
                        packet = zlib.decompress(packet)
                        # print(f"DCC client {packet}")
                    except:
                        print(f"CND client {data_length} {packet}")
                        continue
                        pass
                else:
                    # print(f"DND client {packet}")
                    pass

            (pid, packet) = decode_varint(packet)
            # print(pid)
            msg = handelers["client"][state].get(pid, noop)(packet)
            if msg != None:
                print(f"[client]({state}) {msg}")

def s_parse(server_queue):
    data = b""
    while True:
        or_packet = server_queue.get()
        or_packet = s_cipher.decrypt(or_packet)
        data += or_packet
        while len(data) != 0:
            o_data = data
            try:
                (packet_length, data) = decode_varint(data)
            except:
                break
            if len(data) < packet_length:
                data = o_data
                break
            # print(data)
            packet, data = data[:packet_length], data[packet_length:]
            if compress > 0:
                data_length, packet = decode_varint(packet)
                if data_length > 0:
                    try:
                        packet = zlib.decompress(packet)
                        # print(f"DCC server {packet}")
                    except:
                        print(f"CND server {data_length} {packet}")
                        continue
                        pass
                else:
                    # print(f"DND server {packet}")
                    pass

            (pid, packet) = decode_varint(packet)
            # print(pid)
            msg = handelers["server"][state].get(pid, noop)(packet)
            if msg != None:
                print(f"[server]({state}) {msg}")