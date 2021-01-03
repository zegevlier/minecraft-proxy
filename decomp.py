import zlib
from quarry.types.nbt import TagRoot
from utils import *

sector_size = 4096

with open("r.0.0.mca", "rb") as f:
    data = f.read()

chunks = [[{} for i in range(1024)] for i in range(1024)]

for x, s in enumerate(chunks):
    for z, chunk in enumerate(s):
        offset = 4 * ((x & 31) + (z & 31) * 32)
        timestamp_offset = offset + sector_size
        chunk["location"] = int.from_bytes(data[offset:offset+3], byteorder="big")
        chunk["sector_count"], _ = decode_unsigned_byte(data[offset+3:offset+4])
        chunk["timestamp"] = int.from_bytes(data[timestamp_offset:timestamp_offset+4], byteorder="big")
        if chunk["location"] != 0 and chunk["sector_count"] != 0:
            chunk_data_padded = data[chunk["location"]*sector_size:chunk["location"]*sector_size+chunk["sector_count"]*sector_size]
            chunk_data_length = int.from_bytes(chunk_data_padded[:4], byteorder="big")
            compression_type, _ = decode_unsigned_byte(chunk_data_padded[4:5])
            chunk_data_compressed = chunk_data_padded[5:chunk_data_length+4]
            if compression_type == 1:
                continue # gzip
            elif compression_type == 2:
                # zlib
                chunk_data = zlib.decompress(chunk_data_compressed)
            elif compression_type == 3:
                # uncompressed
                chunk_data = chunk_data_compressed
            else:
                raise TypeError
            parsed_nbt = TagRoot.from_bytes(chunk_data)
            parsed_nbt.update({"Biomes": None})
            print(parsed_nbt.to_obj())
            raise TypeError

