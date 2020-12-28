import struct

def decode_boolean(packet):
    value = packet[:1]
    if value == b'\x01':
        value = True
    elif value == b'\x00':
        value = False
    else:
        print(value)
        raise(ValueError)
    return value, packet[1:]

def decode_byte(packet):
    return unpack(">b", packet)

def decode_unsigned_byte(packet):
    return unpack(">B", packet)

def decode_short(packet):
    return unpack(">h", packet)

def decode_unsigned_short(packet):
    return unpack(">H", packet)

def decode_int(packet):
    return unpack(">i", packet)

def decode_long(packet):
    return unpack(">q", packet)

def decode_float(packet):
    return unpack(">f", packet)

def decode_double(packet):
    return unpack(">d", packet)

def decode_string(packet):
    string_length, packet = decode_varint(packet)
    return packet[:string_length].decode(), packet[string_length:]

def decode_chat(packet):
    return decode_string(packet)

def decode_identifier(packet):
    return decode_string(packet)

def decode_varint(packet):
    number = 0
    for i in range(10):
        b, packet = struct.unpack(">B", packet[:struct.calcsize(">B")])[0], packet[struct.calcsize(">B"):]
        number |= (b & 0x7F) << 7*i
        if not b & 0x80:
            break
    if number & (1<<31):
        number -= 1<<32
    return number, packet

# Varlong

# Entity Metadata

# Slot

# NBT Tag

# Position

# Angle

def decode_uuid(packet):
    return packet[:16].hex(), packet[16:]

def unpack(key, packet):
    value = struct.unpack(key, packet[:struct.calcsize(key)])
    if len(value) == 1:
        value = value[0]
    return value, packet[struct.calcsize(key):]

