import zlib
import struct
from utils import *

sector_size = 4096

with open("r.0.0.mca", "rb") as f:
    infile = f.read()

chunks = [[{} for i in range(1024)] for i in range(1024)]
for i in range(0, sector_size, 4):
    num = i // 4
    location_x = num % 32
    location_z = num // 32
    # print(f"x: {location_x} z: {location_z}")
    data = infile[i:i+4]
    chunks[location_x][location_z]["offset"] = int.from_bytes(data[:3], byteorder="big")
    chunks[location_x][location_z]["sector_count"], _ = decode_unsigned_byte(data[1:])

for i in range(sector_size, sector_size*2, 4):
    num = i // 8
    location_x = num % 32
    location_z = num // 32
    chunks[location_x][location_z]["timestamp"] = int.from_bytes(infile[i:i+4], byteorder="big")

for x, s in enumerate(chunks):
    for z, chunk in enumerate(s):
        try:
            if chunk["sector_count"] != 0:
                print(f"{x} {z} {chunk}")
        except KeyError:
            pass
