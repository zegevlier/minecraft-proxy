import zlib
from quarry.types.nbt import TagRoot, RegionFile, TagString
from utils import *
import struct

sector_size = 4096
outfile = "close/region/r.0.0.mca"


with open(outfile, "wb") as f:
    # data = struct.pack("b", 0)
    # all_data = b""
    # for _ in range(sector_size*2):
        # all_data+=data
    # print(all_data)
    f.seek(sector_size*2-1)
    f.write(b"\0")

with open("r.0.0.mca", "rb") as f:
    data = f.read()
 
chunks = [[{} for _ in range(1024)] for _ in range(1024)]

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
            del parsed_nbt.body.value["Level"].value["Biomes"]
            parsed_nbt.body.value["Level"].value["Sections"].value[1].value["Palette"].value[0].value["Name"].value = u"minecraft:barrier"

            print(parsed_nbt.to_obj())
            region_file = RegionFile(outfile)
            region_file.save_chunk(parsed_nbt)
            region_file.close()
            raise TypeError

