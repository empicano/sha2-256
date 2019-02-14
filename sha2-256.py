import hashlib
import random
import sys


W = 32  # number of bits in word
M = 1 << W
F = M - 1  # 0xFFFFFFFF (for performing addition mod 2**W)

# initialize round constants (first 32 bits of the fractional parts of the cube roots
# of the first 64 primes 2..311
K = (0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
     0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
     0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
     0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
     0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
     0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
     0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
     0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
     0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
     0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
     0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
     0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
     0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
     0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
     0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
     0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2)

# initialize hash values (first 32 bits of the fractional parts of the square roots
# of the first 8 primes 2..19
I = (0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
     0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19)

def ror(x, b):
    '''
    32-bit bitwise rotate right
    '''
    return ((x >> b) | (x << (W - b))) & F

def pad(m):
    '''
    SHA2-256 padding function
    Pads a message and converts to byte array
    Begin with original message of length l bits
    Append a single '1' bit
    Append k '0' bits, where k is the minimum number >= 0 such that l + 1 + k + 64
    is a multiple of 512
    Append l as a 64-bit big-endian integer
    '''
    mdi = len(m) % 64
    l = (len(m) << 3).to_bytes(8, 'big')  # binary of len(m) in bits
    npad = 55 - mdi if mdi < 56 else 119 - mdi
    return bytes(m, 'ascii') + b'\x80' + (b'\x00' * npad) + l

def compress(wt, kt, a, b, c, d, e, f, g, h):
    '''
    SHA2-256 compression function
    '''
    ch = (e & f) ^ (~e & g)
    ma = (a & b) ^ (a & c) ^ (b & c)  # major
    s0 = ror(a, 2) ^ ror(a, 13) ^ ror(a, 22)  # sigma 0
    s1 = ror(e, 6) ^ ror(e, 11) ^ ror(e, 25)  # sigma 1
    t1 = h + s1 + ch + wt + kt
    t2 = s0 + ma
    return (t1 + t2) & F, a, b, c, (d + t1) & F, e, f, g

def sha2_256(m):
    '''
    Performs SHA2-256 on an ascii input string
    m: the string to process
    Returns: the hex digest string
    '''
    m = pad(m)  # pad message
    digest = list(I)  # digest as 8 32-bit words (a-h)
    for i in range(0, len(m), 64):  # iterate over message in chunks of 64
        x = m[i:i + 64]  # current chunk
        w = [0] * 64
        w[0:16] = [int.from_bytes(x[j:j + 4], 'big') for j in range(0, 64, 4)]
        for j in range(16, 64):
            s0 = ror(w[j - 15], 7) ^ ror(w[j - 15], 18) ^ (w[j - 15] >> 3)
            s1 = ror(w[j - 2], 17) ^ ror(w[j - 2], 19) ^ (w[j - 2] >> 10)
            w[j] = (w[j - 16] + s0 + w[j-7] + s1) & F
        a, b, c, d, e, f, g, h = digest  # state of the compression function
        for j in range(64):
            a, b, c, d, e, f, g, h = compress(w[j], K[j], a, b, c, d, e, f, g, h)
        digest = [(x + y) & F for x, y in zip(digest, (a, b, c, d, e, f, g, h))]
    ret = b''.join(c.to_bytes(4, 'big') for c in digest)  # convert to byte array
    return ''.join('{:02x}'.format(i) for i in ret)

if __name__ == '__main__':
    m = sys.argv[1] if len(sys.argv) > 1 else ''  # read command line argument
    digest = sha2_256(m)
    assert digest == hashlib.sha256(m.encode('ascii')).hexdigest()
    print(digest)

