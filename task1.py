from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import random as rand

#-----------OUTLINE------------------------------------------------------

# prime number p (equiv. to q)
# g < p, g primitive root of p (equiv to alpha)

# USER A:
#   select private a < p (random)
#   calculate public A = g^a mod p (use python modular exponentiation)

# USER B:
#   select private b < p (random)
#   calculate public B = g^b mod p (use python modular exponentiation)

# User A sends public key A to user B
# User B sends public key B to user A

# User A:
#   secret key s = B^a mod p
#   hash k = SHA256(s)
#   create message m0
#   encrypt and send AES_CBC(k, m0)

# User B:
#   secret key s = A^b mod p
#   hash k = SHA256(s)
#   create message m1
#   encrypt and send AES_CBC(k, m1)

# git test

#--------BEGIN PROGRAM--------------------------------------------------

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

def encrypt_msg(msg, sender, iv):
    cipher = AES.new(sender.hash, AES.MODE_CBC, iv) # create new AES_CBC cipher
    msg = msg.encode()  # utf-8 encodes message
    msg = pad(msg, 16)  # adds padding
    return cipher.encrypt(msg)  # encrypts & sends

def decrypt_msg(ct, reciever, iv):
    cipher = AES.new(reciever.hash, AES.MODE_CBC, iv) # create new AES_CBC cipher
    msg = cipher.decrypt(ct)    # decrypts message
    msg = unpad(msg, 16)        # unpads message
    return msg.decode()          # utf-8 decodes message

# exchange message from user A to user B
def exchange_message(A, B):
    iv = get_random_bytes(16)   # IV for CBC encoding/decoding
    msg = input("Sender's message: ")           # input message
    ciphertext = encrypt_msg(msg, A, iv)        # get ciphertext
    print("encrypted message sent")
    plaintext = decrypt_msg(ciphertext, B, iv)  # get plaintext
    if (msg==plaintext): 
        print("Message recieved: %s" % plaintext)   # prints recieved message if they're identical

if __name__=='__main__':
    p = 0xB10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C69A6A9DCA52D23B616073E28675A23D189838EF1E2EE652C013ECB4AEA906112324975C3CD49B83BFACCBDD7D90C4BD7098488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708DF1FB2BC2E4A4371
    g = 0xA4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507FD6406CFF14266D31266FEA1E5C41564B777E690F5504F213160217B4B01B886A5E91547F9E2749F4D7FBD7D3B9A92EE1909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28AD662A4D18E73AFA32D779D5918D08BC8858F4DCEF97C2A24855E6EEB22B3B2E5

    #p = int.from_bytes(rand.choice(p_list), byteorder='big')    # random value from p_list turned int
    #g = int.from_bytes(rand.choice(g_list), byteorder='big')    # random value from g_list turned int

    A = User(p, g)  # create user A
    B = User(p, g)  # create user B

    # generate secret keys (identical)
    A.make_secret_key(B.pub_key)
    B.make_secret_key(A.pub_key)

    # generate hashes (identical)
    A.make_hash()
    B.make_hash()

    # test A->B
    print("Testing user A->B")
    exchange_message(A, B)
    # test B->A
    print("Testing user B->A")
    exchange_message(B, A)