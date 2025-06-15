import sys
from itertools import cycle

key = bytearray("jisjidpa123","utf8")
filename = "LSASS_DECRYPTED.DMP"

try:
    data = bytearray(open(sys.argv[1], "rb").read())
except:
    print("File argument needed! %s <raw payload file>" % sys.argv[0])
    sys.exit()

if len(sys.argv) > 2 and sys.argv[2] == "1":
    print("len: {}".format(len(data)))
    print('{ 0x' + ', 0x'.join(hex(x)[2:] for x in data) + ' };')
    sys.exit()
xord_byte_array = bytearray(len(data))
if len(sys.argv) > 2 and sys.argv[2] != "1":
    filename = sys.argv[2]

f = open(filename, "wb")

l = len(key)
for i in range(len(data)):
    current = data[i]
    current_key = key[i % len(key)]
    xord_byte_array[i] = current ^ current_key


f.write(xord_byte_array)
f.close()

print("XORed output saved to \"{}\"".format(filename))
print("Xor Key: {}".format(key.decode()))
sys.exit()
