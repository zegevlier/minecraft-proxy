import os
import config
from utils import *
import math

from quarry.types.nbt import TagRoot
from quarry.types.chunk import BlockArray, PackedArray
from quarry.types.registry import OpaqueRegistry
from struct import pack

default_registry = OpaqueRegistry(14)

def parse_chunk_packet_data(data, bitmask):
    sections = []
    bitmask = reversed(format(primary_bitmask, "b").zfill(8))
    for i, bit in enumerate(bitmask):
        if bit == "1":
            print("seid: ", i)
            block_count, data = decode_short(data)
            bits_per_block, data = decode_unsigned_byte(data)
            actual_bpb = bits_per_block
            global_pallete = False
            if bits_per_block < 4:
                actual_bpb = 4
            elif bits_per_block >= 9:
                actual_bpb = 14
                global_pallete = True
            if not global_pallete:
                palette_length, data = decode_varint(data)
                for i in range(palette_length):
                    _, data = decode_varint(data)
            data_array_len, data = decode_varint(data)

            data_len = math.ceil(data_array_len / (64 // actual_bpb))

            data = data[data_len:]
            print("section done")

    print("chunk done")
    return "a"




if __name__ == "__main__":
    worlds = os.listdir(config.BASE_DIR)
    world_chosen = "close"
    packet_folder = os.path.join(config.BASE_DIR, world_chosen)

    packet_files = os.listdir(packet_folder)
    valid_chunks = []
    for packet_file in packet_files:
        if packet_file.endswith(".chunk_packet"):
            split_pa = packet_file.split(".")
            x_cor = split_pa[0]
            z_cor = split_pa[1]
            if os.path.isfile(os.path.join(config.BASE_DIR, world_chosen, f"{x_cor}.{z_cor}.light_packet")):
                valid_chunks.append(f"{x_cor}.{z_cor}")
    for chunk_file in valid_chunks:
        print(chunk_file)
        with open(os.path.join(config.BASE_DIR, world_chosen, f"{chunk_file}.chunk_packet"), "rb") as chunk_file_id:
            packet = chunk_file_id.read()
        chunk_x, packet = decode_int(packet)
        chunk_z, packet = decode_int(packet)
        full_chunk, packet = decode_boolean(packet)
        primary_bitmask, packet = decode_varint(packet)
        heightmaps = TagRoot.from_bytes(packet)
        heightmaps_len = len(heightmaps.to_bytes())
        packet = packet[heightmaps_len:]
        if full_chunk:
            biomes_length, packet = decode_varint(packet)
            biomes = []
            for i in range(biomes_length):
                b, packet = decode_varint(packet)
                biomes.append(b)
        size, packet = decode_varint(packet)
        data, packet = packet[:size], packet[size:]

        chunk_data = parse_chunk_packet_data(data, primary_bitmask)
        # print(data)
        num_block_entities, packet = decode_varint(packet)
        block_entities = []
        for i in range(num_block_entities):
            entity = TagRoot.from_bytes(packet)
            entity_len = len(entity.to_bytes())
            packet = packet[entity_len:]
            block_entities.append(entity)
    print("All done! :D")


