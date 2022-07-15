# Mallory has sniffed from the network a message m and a keyed
# digest sniffed_kdgst computed with the following Python code
#
# from hashlib import sha1
# h = sha1()
# h.update(key+m)
# sniffed_kdgst = h.hexdigest()
#
# and wants to perform a length extension attack that appends
# the content of the data_to_append variable
#
# Starting from the pure Python implementation of the Sha1
# algorithm available at the link below
#
# The objective of this exercise is to:
# - List the functions to modify to mount the length extension attack
# - Write the modifications to the python code to implement the length extension attack
#
# Assume that Mallory knows that len(key+m) is less than the size of one SHA1 block.
#
# Also assume that she accesses the sniffed keyed digest value and data to append by means of the
# following imported global variables
#
# from mydata import sniffed_kdgst
# from mydata import data_to_append # bytes
#
# and that the modified main() function must print out the result
# with the following code (i.e., avoid modifying the main unless you have)
# a very good solution)

# Function to be modified:
#
# 1) init(self,s) -> substitute IV with sniffed dgst

def __init__(self,s):
    self.__H = [None] * 5
    for i in range(5):
        self.__H[i] = int("0x" + sniffed_dgst[i * 8:(i + 1) * 8], 16)
    print(self.__H)

# 2) padding(stream)

def __padding(stream):
        l = len(stream)  # Bytes
        l += 512//8 # add this line

        hl = [int((hex(l * 8)[2:]).rjust(16, '0')[i:i + 2], 16)
              for i in range(0, 16, 2)]

        l0 = (56 - l) % 64
        if not l0:
            l0 = 64

        if isinstance(stream, str):
            stream += chr(0b10000000)
            stream += chr(0) * (l0 - 1)
            for a in hl:
                stream += chr(a)
        elif isinstance(stream, bytes):
            stream += bytes([0b10000000])
            stream += bytes(l0 - 1)
            stream += bytes(hl)

        return stream
        
def main():
    hasher = SHA1()
    hasher.update(data_to_append)
    print(hasher.hexdigest())
    