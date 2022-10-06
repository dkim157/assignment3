p = 37  # a prime number (equiv. to q)
g = 5   # g < p, g primitive root p (equiv to alpha)

# USER A:
# select private a < p (random)
# calculate public A = g^a mod p

if __name__=='__main__':
    dh()