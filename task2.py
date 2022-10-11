from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import random as rand

class User:
    def __init__(self, p, g):
        self.p = p
        self.g = g
        self.priv_key = rand.randint(0, p)
        self.pub_key = pow(self.g, self.priv_key, self.p)
        self.secret_key = None
        self.hash = None

    # makes, assigns, and returns secret key
    def make_secret_key(self, other_pub_key):
        self.secret_key = pow(other_pub_key, self.priv_key, self.p) #make and assign secret_key
        return self.secret_key

    # makes, assigns, and returns hash based on secret key
    def make_hash(self):
        if self.secret_key is None:             # returns None if make_hash is called before secret key is made
            return None
        else:
            sc = self.secret_key                        # copy secret key into sc
            byte_arr_len = (sc.bit_length() + 7) // 8   # calculate smallest byte-array length to hold sc
            sc_bytes = sc.to_bytes(byte_arr_len, byteorder='big')   # convert sc into bytes
            h = SHA256.new()            # create hash object
            h.update(sc_bytes)          # create hash
            self.hash = h.digest()[:16] # assign first 16 bytes of hash to self.hash
            return self.hash

def encrypt_msg(msg, sender_hash, iv):
    cipher = AES.new(sender_hash, AES.MODE_CBC, iv) # create new AES_CBC cipher
    msg = msg.encode()  # utf-8 encodes message
    msg = pad(msg, 16)  # adds padding
    return cipher.encrypt(msg)  # encrypts & sends

def decrypt_msg(ct, reciever_hash, iv):
    cipher = AES.new(reciever_hash, AES.MODE_CBC, iv) # create new AES_CBC cipher
    msg = cipher.decrypt(ct)    # decrypts message
    msg = unpad(msg, 16)        # unpads message
    return msg.decode()         # utf-8 decodes message

# exchange message from user A to user B
def exchange_message(A, B):
    iv = get_random_bytes(16)   # IV for CBC encoding/decoding
    msg = input("Sender's message: ")           # input message
    ciphertext = encrypt_msg(msg, A.hash, iv)   # get ciphertext
    print("encrypted message sent")
    plaintext = decrypt_msg(ciphertext, B.hash, iv) # get plaintext
    if (msg==plaintext): 
        print("Message recieved: %s" % plaintext)   # prints recieved message if they're identical

def attack_1(p, g):
    A = User(p, g)  # create user A
    B = User(p, g)  # create user B

    # !!!PUBLIC KEY INTERCEPTION AND MODIFICATION!!!
    A.make_secret_key(p)    # B.pub_key -> p
    B.make_secret_key(p)    # A.pub_key -> p

    # generate hashes (identical)
    A.make_hash()
    B.make_hash()

    print(A.secret_key)
    print(B.secret_key)
    print(A.hash)
    print(B.hash)

    # test A->B
    print("Exchange A->B")
    exchange_message(A, B)
    # test B->A
    print("Exchange B->A")
    exchange_message(B, A)

# decrypts ciphertext given tampered g
def intercept_ct(ct, A, B, iv):
    # since g is tampered, we know public key (g=1 or p-1, pub_key=1) (g=p, pub_key=0)
    # since we know public key, we know secret key (g=1 or p-1, secret_key=1) (g=p, secret_key=0)
    # thus, we can use SHA256 on our known secret key and get the AES-CBC hash
    sc = 1  # known secret key
    byte_arr_len = (sc.bit_length() + 7) // 8   # calculate smallest byte-array length to hold sc
    sc_bytes = sc.to_bytes(byte_arr_len, byteorder='big')   # convert sc into bytes
    h = SHA256.new()
    h.update(sc_bytes)
    fixed_hash = h.digest()[:16]
    # since iv is typically part of the secret key, we have all we need to AES-CBC decrypt the message.
    # in this case we'll just pass it in
    return decrypt_msg(ct, fixed_hash, iv)

# compromised exchange of messages
def compromised_exchange(A, B):
    iv = get_random_bytes(16)   # IV for CBC encoding/decoding
    msg = input("Sender's message: ")           # input message
    ciphertext = encrypt_msg(msg, A.hash, iv)   # get ciphertext
    print("encrypted message sent")
    intercepted = intercept_ct(ciphertext, A, B, iv)  # intercepts cipher (given tampered g)
    print("message intercepted: %s" % intercepted)  # prints intercepted message
    plaintext = decrypt_msg(ciphertext, B.hash, iv) # get plaintext
    if (msg==plaintext): 
        print("Message recieved: %s" % plaintext)   # prints recieved message if they're identical

def attack_2(p, g):
    # !!!TAMPERING WITH g!!!
    g = 1 # p # p-1 (alternatives)

    A = User(p, g)  # create user A
    B = User(p, g)  # create user B

    # generate secret keys (identical)
    A.make_secret_key(B.pub_key)
    B.make_secret_key(A.pub_key)

    # generate hashes (identical)
    A.make_hash()
    B.make_hash()

    # COMPROMISED A->B
    print("Exchange A->B")
    compromised_exchange(A, B)
    # COMPROMISED B->A
    print("Exchange B->A")
    compromised_exchange(B, A)

if __name__=='__main__':
    p_list = [b'0xB10B8F96', b'0xA080E01D', b'0xDE92DE5E', b'0xAE5D54EC', b'0x52C99FBC', b'0xFB06A3C69A6A9DCA', 
        b'0x52D23B61', b'0x6073E286', b'0x75A23D18', b'0x9838EF1E', b'0x2EE652C013ECB4AE', b'0xA9061123', 
        b'0x24975C3C', b'0xD49B83BF', b'0xACCBDD7D', b'0x90C4BD7098488E9C', b'0x219A7372', b'0x4EFFD6FA', 
        b'0xE5644738', b'0xFAA31A4F', b'0xF55BCCC0A151AF5F', b'0x0DC8B4BD', b'0x45BF37DF', b'0x365C1A65', 
        b'0xE68CFDA7', b'0x6D4DA708DF1FB2BC', b'0x2E4A4371']  # list of prime numbers p
    g_list = [b'0xA4D1CBD5', b'0xC3FD3412', b'0x6765A442', b'0xEFB99905', b'0xF8104DD2', b'0x58AC507F', b'0xD6406CFF',
        b'0x14266D31', b'0x266FEA1E', b'0x5C41564B', b'0x777E690F', b'0x5504F213160217B4', b'0xB01B886A', b'0x5E91547F', 
        b'0x9E2749F4', b'0xD7FBD7D3', b'0xB9A92EE1909D0D22', b'0x63F80A76', b'0xA6A24C08', b'0x7A091F53', b'0x1DBF0A01', 
        b'0x69B6A28AD662A4D1', b'0x8E73AFA3', b'0x2D779D59', b'0x18D08BC8', b'0x858F4DCE', b'0xF97C2A24855E6EEB', 
        b'0x22B3B2E5']   # list of primitive roots g

    p = int.from_bytes(rand.choice(p_list), byteorder='big')    # random value from p_list turned int
    g = int.from_bytes(rand.choice(g_list), byteorder='big')    # random value from g_list turned int

    attack_1(p, g)  # demonstrates attack 1
    #attack_2(p, g)  # demonstrates attack 2