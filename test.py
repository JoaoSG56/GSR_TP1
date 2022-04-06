import struct
data = [39, 39, 126, 126, 256, 258, 260, 259, 257, 126]
ip = [123,111,222,333]
# 4s -> ip {}H -> qt de oids
encoded = struct.pack("!4H{}H".format(len(data)), *ip,*data)
try:
    print(struct.unpack("!4h", encoded[0:8]))
except Exception as e:
    print(e)