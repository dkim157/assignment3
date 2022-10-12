from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import random as rand

# -----------OUTLINE------------------------------------------------------

# ----Key Generation----

# choose p and q are both prime and p != q

# create common key n
#   n = p * q

# phi = (p - 1)(q - 1)
#   used to get keys

# generate public key
#   get integer e
#   e must 1 < e < phi and gcd(phi, e) = 1

# generate private key
#   find d where d * e % phi = 1

# public key: (e, n)
# private key: (d, n)

# ----Encryption----

# plaintext M as an int and M < n
# ciphertext C
#   C = M^e (mod n)

# ----Decryption----

# ciphertext C
# plaintext M
#   M = C^d (mod n)

# ----Key Exchanmge----

# USER A:
#   creates their own private and public key

# user A sends public key to user B

# USER B:
#   picks random element x < n this is the secret key to be shared
#   create y = RSA(A_public, x) this is the encrypted secret key

# user B sends y to user A

# USER A:
#   x = RSA^-1(A_private, y) decrypt y to get secret key
#   k = SHA256(x) hash secret key

# USER B:
#   k = SHA256(x) hash secret key

# USER A:
#   create message m0
#   encrypt to ciphertext c0 with secret key
#       c0 = AES-CBCk(m0)

# USER B:
#   create message m1
#   encrypt to ciphertext c1 with secret key
#       c1 = AES-CBCk(m1)

# --------BEGIN PROGRAM--------------------------------------------------


class User:
    def __init__(self, p, q):
        self.p = p
        self.q = q
        self.common_key = p * q
        self.phi = (p - 1) * (q - 1)
        self.public_key = 65537
        self.private_key = pow(self.public_key, -1, self.phi)
        self.secret_key = None
        self.hash = None

    def generate_private_key(self):
        # solves for d and assigns to private key when d*e (mod phi(n)) = 1
        self.private_key = pow(self.public_key, -1, self.phi)
        return None

    # makes, assigns, and returns hash based on secret key
    def make_hash(self):
        if self.secret_key is None:             # returns None if make_hash is called before secret key is made
            return None
        else:
            sc = self.secret_key                        # copy secret key into sc
            # calculate smallest byte-array length to hold sc
            byte_arr_len = (sc.bit_length() + 7) // 8
            # convert sc into bytes
            sc_bytes = sc.to_bytes(byte_arr_len, byteorder='big')
            h = SHA256.new()            # create hash object
            h.update(sc_bytes)          # create hash
            # assign first 16 bytes of hash to self.hash
            self.hash = h.digest()[:16]
            return self.hash

    def make_secret_key(self, pub_key):
        secret_key = rand.randint(2, pub_key[1])        # chooses secret key
        self.secret_key = secret_key                    # assigns secret key to self
        # encrypt secret key with given public key pait
        enc_secret = encrypt_msg(secret_key, pub_key)
        return enc_secret                               # returns encrypted secret key

    def decrypt_msg(self, ct):
        pt = pow(pow(ct, self.private_key), 1, self.common_key)
        return pt


def encrypt_msg(msg, public_key):   # RSA encrypts message with given public key pair
    if msg >= public_key[1]:    # checks if plaintext larger than n
        print("message too big")
        print(int_msg)
        print(public_key[1])
        return
    ciphertext = pow(pow(msg, public_key[0]), 1, public_key[1])
    return ciphertext


def aes_encrypt_msg(msg, sender, iv):
    # create new AES_CBC cipher
    cipher = AES.new(sender.hash, AES.MODE_CBC, iv)
    msg = msg.encode()  # utf-8 encodes message
    msg = pad(msg, 16)  # adds padding
    return cipher.encrypt(msg)  # encrypts & sends


def aes_decrypt_msg(ct, reciever, iv):
    # create new AES_CBC cipher
    cipher = AES.new(reciever.hash, AES.MODE_CBC, iv)
    msg = cipher.decrypt(ct)    # decrypts message
    msg = unpad(msg, 16)        # unpads message
    return msg.decode()          # utf-8 decodes message


def exchange_key(A, B):
    public_A = (A.public_key, A.common_key)  # creates A public key pair
    # B creates a secret key and encrypts with A's public key
    y = B.make_secret_key(public_A)
    A.secret_key = A.decrypt_msg(y)     # A decrypts secret key and saves it
    A.make_hash()       # A and B hash identical secret keys
    B.make_hash()
    a_msg = "Hi Bob!"   # A's message to B
    b_msg = "Hi Alice!"  # B's message to A
    send_msg(a_msg, A, B)   # A sends and encrypts message to B and B decrypts
    send_msg(b_msg, B, A)   # B sends and encrypts message to A and A decrypts


def send_msg(msg, sender, receiver):
    print(f'msg: {msg}')
    iv = get_random_bytes(16)
    ct = aes_encrypt_msg(msg, sender, iv)   # sender encrypts message
    print(f'ct: {ct}')
    enc = aes_decrypt_msg(ct, receiver, iv)  # receiver decrypts ciphertext
    print(f'enc: {enc}')


def mallory_attack(A, B):
    public_A = (A.public_key, A.common_key)  # creates A's public key pair
    c = B.make_secret_key(public_A)         # B encrypts secret key for A
    print(f'bob ct: {c}')
    mal_msg = rand.randint(2, A.common_key - 1)  # mallory creates new message
    # mallory encrypts their msg to send to A
    mal_ct = encrypt_msg(mal_msg, public_A)
    print(f'mallory ct: {mal_ct}')
    a_pt = A.decrypt_msg(mal_ct)                # A decrypts mallory's message
    print(f'alice decrypt: {a_pt}')
    print(f'mallory s: {mal_msg}')


if __name__ == '__main__':
    A = User(17, 11)
    B = User(13, 7)

    print("\nRSA Key Exchange:")
    exchange_key(A, B)
    print("\nMallory MITM attack:")
    mallory_attack(A, B)
