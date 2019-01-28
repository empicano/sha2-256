import hashlib
import random
import sys


W = 64  # number of bits in word
M = 1 << W
F = M - 1  # 0xFFFFFFFFFFFFFFFF (for performing addition mod 2**W)

# initialize round constants (first 32 bits of the fractional parts of the cube roots
# of the first 64 primes 2..311
K = (0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
     0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
     0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
     0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
     0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
     0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
     0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
     0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
     0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
     0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
     0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
     0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
     0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
     0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
     0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
     0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
     0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
     0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
     0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
     0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817)

# initialize hash values (first 32 bits of the fractional parts of the square roots
# of the first 8 primes 2..19
I = (0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
     0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179)

def ror(x, b):
    '''
    32-bit bitwise rotate right
    '''
    return ((x >> b) | (x << (W - b))) & F

def pad(m):
    '''
    SHA512 padding function
    Pads a message and converts to byte array
    Begin with original message of length l bits
    Append a single '1' bit
    Append k '0' bits, where k is the minimum number >= 0 such that l + 1 + k + 128
    is a multiple of 1024
    Append l as a 128-bit big-endian integer
    '''
    mdi = len(m) % 128
    l = (len(m) << 3).to_bytes(16, 'big')  # binary of len(m) in bits
    npad = 111 - mdi if mdi < 112 else 239 - mdi
    return bytes(m, 'ascii') + b'\x80' + (b'\x00' * npad) + l

def compress(wt, kt, a, b, c, d, e, f, g, h):
    '''
    SHA512 compression function
    '''
    ch = (e & f) ^ (~e & g)
    ma = (a & b) ^ (a & c) ^ (b & c)  # major
    s0 = ror(a, 28) ^ ror(a, 34) ^ ror(a, 39)  # sigma 0
    s1 = ror(e, 14) ^ ror(e, 18) ^ ror(e, 41)  # sigma 1
    t1 = h + s1 + ch + wt + kt
    t2 = s0 + ma
    return (t1 + t2) & F, a, b, c, (d + t1) & F, e, f, g

def sha512(m):
    '''
    Performs SHA512 on an ascii input string
    m: the string to process
    Returns: the hex digest string
    '''
    m = pad(m)  # pad message
    digest = list(I)  # digest as 8 64-bit words (a-h)
    for i in range(0, len(m), 128):  # iterate over message in chunks of 128
        x = m[i:i + 128]  # current chunk
        w = [0] * 80
        w[0:16] = [int.from_bytes(x[j:j + 8], 'big') for j in range(0, 128, 8)]
        for j in range(16, 80):
            s0 = ror(w[j - 15], 1) ^ ror(w[j - 15], 8) ^ (w[j - 15] >> 7)
            s1 = ror(w[j - 2], 19) ^ ror(w[j - 2], 61) ^ (w[j - 2] >> 6)
            w[j] = (w[j - 16] + s0 + w[j-7] + s1) & F
        a, b, c, d, e, f, g, h = digest  # state of the compression function
        for j in range(80):
            a, b, c, d, e, f, g, h = compress(w[j], K[j], a, b, c, d, e, f, g, h)
        digest = [(x + y) & F for x, y in zip(digest, (a, b, c, d, e, f, g, h))]
    ret = b''.join(c.to_bytes(8, 'big') for c in digest)  # convert to byte array
    return ''.join('{:02x}'.format(i) for i in ret)

if __name__ == '__main__':
    m = sys.argv[1] if len(sys.argv) > 1 else ''  # read command line argument
    digest = sha512(m)
    assert digest == hashlib.sha512(m.encode('ascii')).hexdigest()
    print(digest)

