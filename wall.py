import hashlib, binascii, sys, os, hmac
from bitarray import bitarray
from bitarray.util import ba2int
from hashlib import sha256
from itertools import permutations
import base58
import csv
import time
from dotenv import dotenv_values
config = dotenv_values("env.txt")


hashesComputed = 0
testedduplicate = 0
testedcands = ['']
testedcandidates = 0

# # valid_entropy_bit_sizes = [128, 160, 192, 224, 256]
# entropy_bit_size = 128
# entropy_bytes = os.urandom(entropy_bit_size // 8)
# print(entropy_bytes)
# # b'Q\x83\xe1\xf4\xf1j\xac5\x16\x04<\x0bm`\xcf\x0c'
# entropy_bits = bitarray()
# entropy_bits.frombytes(entropy_bytes)
# print(entropy_bits)
# # bitarray('0101000110000011...01100111100001100')
# checksum_length = entropy_bit_size // 32
# print(checksum_length)
#
# hash_bytes = sha256(entropy_bytes).digest()
# print(hash_bytes)
# # b'\xef\x88\xad\x02\x16\x7f\xa6y\xde\xa6T...'
# hash_bits = bitarray()
# hash_bits.frombytes(hash_bytes)
# print(hash_bits)
# # bitarray('111011111000100010...')
# checksum = hash_bits[:checksum_length]
# print(checksum)
# # bitarray('1110')
#
# print(len(entropy_bits))
# # 128
# entropy_bits.extend(checksum)
# print(len(entropy_bits))
# # 132
#
# grouped_bits = tuple(entropy_bits[i * 11: (i + 1) * 11] for i in range(len(entropy_bits) // 11))
# print(grouped_bits)
# # (bitarray('01010001100'), bitarray('00011111000'), ...)
# print(len(grouped_bits))
# # 12
#
# indices = tuple(ba2int(ba) for ba in grouped_bits)
# print(indices)
# # (652, 248, 1001, 1814, 1366, 212, 704, 1084, 91, 856, 414, 206)

f = open('english.txt','r')
vars = open('env.txt','r')
w1 = open('seedlist.txt','w')
twords = f.readlines()

words = []
words_fantasy = []
words_sign = []
words_arrow = []
words_trash = []
simplewords = []
i = 0
wrdindex = {}
for word in twords:
    word = word.replace("\n","")
    wrdindex[word] = i
    words.append(word)
    i+=1
# i = 0
# wrdindex = {}
# for word in twords0:
#     word = word.replace("\n","")
#     # wrdindex[word] = i
#     words0.append(word)
    # i+=1
# print (words0)
# for word in twords2:
#     word = word.replace("\n","")
#     # wrdindex[word] = i
#     words2.append(word)
#     # i+=1
# print (words2)
# for word in twordsx:
#     word = word.replace("\n","")
#     # wrdindex[word] = i
#     simplewords.append(word)
#
# for word in twords31:
#     word = word.replace("\n","")
#     # wrdindex[word] = i
#     words31.append(word)
#
# for word in twords32:
#     word = word.replace("\n","")
#     # wrdindex[word] = i
#     words_fantasy.append(word)
# for word in twords33:
#     word = word.replace("\n","")
#     # wrdindex[word] = i
#     words_sign.append(word)
# for word in twords34:
#     word = word.replace("\n","")
#     # wrdindex[word] = i
#     words_arrow.append(word)
# for word in twords35:
#     word = word.replace("\n","")
#     # wrdindex[word] = i
#     words_trash.append(word)


# mneN = [ ('digital',),
#         ('put',('trash','waste','scrap','garbage')),
#         ('suit','pen'),
#         ('book','license'),
#         (('cake', 'castle', 'city', 'kingdom', 'mansion', 'museum', 'nation', 'palace', 'stadium', 'tower', 'venue', 'village'),),
#         ('weird',) ]
mneN = config["SEEDPHRASE"]

passphrase = ""


def generateSeed(mnemonicstring):
    salt = "mnemonic" + passphrase
    seed = hashlib.pbkdf2_hmac(
        "sha512",
        mnemonicstring.encode("utf-8"),
        salt.encode("utf-8"),
        2048
    )
    # print(seed)
    # b'\xcd@\xd0}\xbc\x17\xd6H\x00\x1c\xdc...'
    # print(len(seed))
    # 64
    # print(seed.hex())
    return seed.hex()

def isOk(ws):
    global hashesComputed
    N = 0
    for w in ws:
        N = (N<<11) + wrdindex[w]

    nhex = format(N, '033x') # include leading zero if needed

    h = hashlib.sha256(binascii.unhexlify(nhex[:-1])).hexdigest()
    hashesComputed +=1
    # if(hashesComputed % 1000 == 0):
    #     print("Computed hashes: "+str(hashesComputed))
    return h[0] == nhex[-1]

def generateRoot(seed):
    # the HMAC-SHA512 `key` and `data` must be bytes:
    seed_bytes = binascii.unhexlify(seed)
    I = hmac.new(b'Bitcoin seed', seed_bytes, hashlib.sha512).digest()
    L, R = I[:32], I[32:]
    master_private_key = int.from_bytes(L, 'big')
    master_chain_code = R
    # print(str(master_private_key)+" CC:  "+str(master_chain_code))
    # return [master_private_key, master_chain_code]

    VERSION_BYTES = {
        'mainnet_public': binascii.unhexlify('0488b21e'),
        'mainnet_private': binascii.unhexlify('0488ade4'),
        'testnet_public': binascii.unhexlify('043587cf'),
        'testnet_private': binascii.unhexlify('04358394'),
    }
    version_bytes = VERSION_BYTES['mainnet_private']
    depth_byte = b'\x00'
    parent_fingerprint = b'\x00' * 4
    child_number_bytes = b'\x00' * 4
    key_bytes = b'\x00' + L
    all_parts = (
        version_bytes,      # 4 bytes
        depth_byte,         # 1 byte
        parent_fingerprint,  # 4 bytes
        child_number_bytes, # 4 bytes
        master_chain_code,  # 32 bytes
        key_bytes,          # 33 bytes
    )
    all_bytes = b''.join(all_parts)
    root_key = base58.b58encode_check(all_bytes).decode('utf8')
    # print(root_key)
    # xprv9s21ZrQH143K...T2emdEXVYsCzC2U
    # print(root_key)
    return [master_private_key, master_chain_code, root_key]

def deriveWallet(pkey, chain_code, root_key):
    # Break each depth into integers (m/44'/60'/0'/0/0)
    #    e.g. (44, 60, 0, 0, 0)# If hardened, add 2**31 to the number:
    #    e.g. (44 + 2**31, 60 + 2**31, 0 + 2**31, 0, 0)
    path_numbers = (2147483692, 2147483708, 2147483648, 0, 0)
    depth = 0
    parent_fingerprint = None
    child_number = None
    private_key = pkey
    chain_code = chain_code

    from ecdsa import SECP256k1
    from ecdsa.ecdsa import Public_key

    SECP256k1_GEN = SECP256k1.generator

    def serialize_curve_point(p):
       x, y = p.x(), p.y()
       if y & 1:
          return b'\x03' + x.to_bytes(32, 'big')
       else:
          return b'\x02' + x.to_bytes(32, 'big')

    def curve_point_from_int(k):
       return Public_key(SECP256k1_GEN, SECP256k1_GEN * k).point

    def fingerprint_from_private_key(k):
       K = curve_point_from_int(k)
       K_compressed = serialize_curve_point(K)

       identifier = hashlib.new(
          'ripemd160',
          hashlib.sha256(K_compressed).digest(),
       ).digest()

       return identifier[:4]

    SECP256k1_ORD = SECP256k1.order
    def derive_ext_private_key(private_key, chain_code, child_number):
        if child_number >= 2 ** 31:
            # Generate a hardened key
            data = b'\x00' + private_key.to_bytes(32, 'big')
        else:
            # Generate a non-hardened key
            p = curve_point_from_int(private_key)
            data = serialize_curve_point(p)

        data += child_number.to_bytes(4, 'big')

        hmac_bytes = hmac.new(chain_code, data, hashlib.sha512).digest()
        L, R = hmac_bytes[:32], hmac_bytes[32:]

        L_as_int = int.from_bytes(L, 'big')
        child_private_key = (L_as_int + private_key) % SECP256k1_ORD
        child_chain_code = R

        return (child_private_key, child_chain_code)

    def derivePublicKey(private_key):
        # Derive the public key Point:
        p = curve_point_from_int(private_key)
        # print(f'Point object: {p}\n')

        # Serialize the Point, p
        public_key_bytes = serialize_curve_point(p)

        # print(f'public key (hex): 0x{public_key_bytes.hex()}')
        return public_key_bytes.hex()

    def deriveWalletAddresss(private_key):
        from eth_utils import keccak
        p = curve_point_from_int(private_key)
        # Hash the concatenated x and y public key point values:
        digest = keccak(p.x().to_bytes(32, 'big') + p.y().to_bytes(32, 'big'))

        # Take the last 20 bytes and add '0x' to the front:
        address = '0x' + digest[-20:].hex()

        # print(f'address: {address}')
        return address

    for i in path_numbers:
        depth += 1
        child_number = i
        parent_fingerprint = fingerprint_from_private_key(private_key)
        private_key, chain_code = derive_ext_private_key(private_key, chain_code, child_number)

    # print(f'private key: {hex(private_key)}')
    pubkey = derivePublicKey(private_key)
    address = deriveWalletAddresss(private_key)
    return (private_key, pubkey, address)



# def testCand(cand):
#     global targetWallet
#
#     if isOk(cand):
#         # timeisOk += time.perf_counter()-tic
#         # print("Found valid seed phrase! Attempt#"+ str(ind)+"\n")
#         # print(cand)
#         # tic = time.perf_counter()
#         seed = generateSeed(' '.join(cand))
#         # timegenSeed += time.perf_counter() - tic
#
#         # tic = time.perf_counter()
#         mpkccroot = generateRoot(seed)
#         # timegenRoot += time.perf_counter() - tic
#
#         # tic = time.perf_counter()
#         keys = deriveWallet(mpkccroot[0],mpkccroot[1],mpkccroot[2])
#         # timegenWallet += time.perf_counter() - tic
#         # print(keys[2])
#         # csvwrite.writerow(keys)
#         if keys[2].lower() == targetWallet:
#             print("Found match!")
#             print(keys)
#             exit()
#             return 42


targetWallet = config['TARGETWALLET']
targetWallet = targetWallet.lower()

# given list of tuples in lengths of 2, 3, 4, 5, 6..
# assume order of tuples is correct, don't permute.
# take each tuple, permute internally, create candidate as list
ggCount = 0
# ggtestTupSent = 0
# #
# def fillAddons(rcand):
#     # called to fill addons to tuple at index ind, missing elements diff
#     raw = rcand.copy()
#     lenElement = int(12/len(raw))
#     print("length = "+str(lenElement))
#     for x, it in enumerate(raw):
#         if (len(it) != lenElement):
#             diff = lenElement - len(it)
#             # permB = permutations(words,diff)
#             print(str(diff))
#             print("it = "+str(it))
#             for i in range(diff):
#                 if (x == 0):
#                     it += (tuple(words_sign),)
#                 if (x == 1):
#                     it += (tuple(words_trash),)
#                 elif (x == 4):
#                     it += (tuple(words_fantasy),)
#                 elif (x == 5):
#                     it += (tuple(words_arrow),)
#                 else:
#                     it += (tuple(words),)
#             raw[x] = it
#     print(str(raw))
#     print("Length of Candidate:"+str(len(raw)))
#     print("Length of each tuple: ")
#     for i in raw:
#         print(str(len(i)))
#     return raw
# testedcandidates


def fillAddons(rcand):
    global ggCount
    #non-tuple
    raw = rcand.copy()
    missinglen = len(raw)
    # for x, it in enumerate(raw):
    diff = 12-missinglen
    # print(diff)
    permB = permutations(words, diff)
    for i in permB:
        # generate seed
        tcand = raw + list(i)
        if (isOk(tcand)):
            # print(str(tcand))
            tc = ' '.join(tcand)
            w1.write(tc)
            w1.write("\n")
            print(tc)
            # print("valid seed")
            ggCount+=1
    print(ggCount)


actual = 0
save = False
written = 0

# taking each permutated element, check if the element is a tuple, if so, permute the tuple and check
def candTester(cand):
    global actual, save,written
    noTup = True
    for x, c in enumerate(cand):
        # if element in candidate is tuple, iterate over subelements and resurse
        if (isinstance(c, tuple)):
            noTup = False
            for d in c:
                candcopy = cand.copy()
                candcopy[x] = d
                candTester(candcopy)
            # stop in the first occurance of tuple element
            break
    if (noTup):
        # print("cand: "+str(cand))
        # if (cand == control):
        #     print("Matched with control: "+str(cand))
            # exit()
        # Don't test cand, save to file.
        actual += 1
        if(actual%1000 == 0):
            print("written "+str(actual)+" actuals")
        # if (isOk(cand)):
        w1.write(' '.join(cand))
        w1.write("\n")
        written += 1
        # testCand(cand)



def menmonicRecursive(mnem, cand=[]):
    global actual, save
    length = len(mnem)
    if (length > 0):
        perms = permutations(mnem[0])
        for k in perms:
            menmonicRecursive(mnem[1:], tuple(cand)+k)
    else:
        # print("mnem: "+str(mnem)+"\ncand: "+str(cand))
        # actual += 1
        candTester(list(cand))
        # if (actual >= 115000000):
        #     save = True
        # elif(actual > 460000000):
        #     print("reached 222,000,000 limit, quitting")
        #     quit()


start = time.perf_counter()
mneN = mneN.split(",")
fillAddons(mneN)
# mneN = fillAddons(mneN)
# anotherPermuteFunc(mneN)
# menmonicRecursive(mneN)
w1.close()
stop = time.perf_counter()
runtime = stop - start
hashpm = (hashesComputed/runtime)*60
print(f"Ran for {runtime:0.4f} seconds; Average: "+str(hashpm)+"H/m")
print('Written: '+str(ggCount)+' seeds')
