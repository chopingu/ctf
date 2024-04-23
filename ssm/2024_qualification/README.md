# Swedish Championship in Cyber Security 2024 Qualification

Since I am not participating this year, I have decided to create a lot of cryptography challenges. 
Following are the four challenges I created for the qualification of the Swedish Championship in Cyber Security. More detailed explanations may follow in the future.


## [Crypto] Really Secure Autput

**Creator:** chopingu

**Challenge description:**
```
Try to crack this one ;)
```

Source: 
```python
from Crypto.Util.number import *
from random import randint
from flag import FLAG

p = getPrime(512)
q = getPrime(512)
n = p * q
e = 0x10001

m = bytes_to_long(FLAG)
c = pow(m, e, n)

autput = randint(1, 2^18) * p**5 + randint(1, 2^18) * q**3

with open('autput', 'w') as f:
    f.write(str(autput) + '\n')
    f.write(str(n) + '\n')
    f.write(str(c))
    f.close()
```

Solution 1:
```python
from Crypto.Util.number import *
from sage.all import *
from tqdm import *

with open('autput', 'r') as f:
    autput = int(f.readline())
    n = int(f.readline())
    enc_flag = int(f.readline())
    f.close()

for i in tqdm(range(1, 16)):
    for j in range(1, 16):
        p = var('p')
        sol = solve(i * p**8 - p**3 * autput + j * n**3, p)

        try:
            p = int(sol[0].rhs())
        except:
            continue

        if gcd(p, n) == p: 
            q = n // p 
            phi = (p - 1) * (q - 1)
            e = 0x10001
            d = pow(e, -1, phi)
            flag = pow(enc_flag, d, n)
            print(long_to_bytes(flag).decode())
            exit()
```

Solution 2:
```python
from Crypto.Util.number import *
from sage.all import *
from gmpy2 import iroot

with open('autput', 'r') as f:
    autput = int(f.readline())
    n = int(f.readline())
    enc_flag = int(f.readline())
    f.close()

for i in range(1, 16):
    p = iroot(autput // i, 5)[0]
    if gcd(n, p) == p:
        q = n // p
        phi = (p - 1) * (q - 1)
        e = 0x10001
        d = pow(e, -1, phi)
        flag = pow(enc_flag, d, n)
        print(long_to_bytes(flag).decode())
        exit()
```

## [Crypto] md10

**Creator:** chopingu

**Challenge description:**
```
I heard md5 was insecure so I thought I would give md10 a try :)
```

Source: 
```python
from hashlib import md5

FLAG = b'SSM{d0nt_3v3n_try_t0_xxxxxxx_gu3ss_y0u_l1ttl3...}'

# md(5+5) = md10
a = int(md5(FLAG[:25]).hexdigest(), 16)
b = int(md5(FLAG[25:]).hexdigest(), 16)

with open('enc_flag', 'w') as f:
    f.write(str(a+b))
    f.close()
```

Solution:
```python
from itertools import product
from string import printable
from hashlib import md5
from tqdm import *

with open('enc_flag', 'r') as f:
    a_b = int(f.read())
    f.close()

a = b'SSM{d0nt_3v3n_try_t0_'
b = b'_gu3ss_y0u_l1ttl3...}'

ltable = {}

perms = list(product(printable, repeat = 3))
for i in tqdm(range(len(perms))):
    b_guess = ''.join(perms[i]).encode() + b
    b_val = int(md5(b_guess).hexdigest(), 16)
    ltable[b_val] = b_guess

perms = list(product(printable, repeat = 4))
for i in tqdm(range(len(perms))):
    a_guess = a + ''.join(perms[i]).encode()
    a_val = int(md5(a_guess).hexdigest(), 16)
    
    b_val = a_b - a_val
    if b_val in ltable:
        print((a_guess + ltable[b_val]).decode())
        exit()
```

## [Crypto] BlackSmith

**Creator:** chopingu

**Challenge description:**
```
Welcome to our store! Please tell us what you want to forge
```

Source:
```python
#!/usr/bin/env python3
from Crypto.Util.number import *
from flag import FLAG

def gen_key():
    e = 0x10001
    p = getPrime(1024)
    q = getPrime(1024)
    d = pow(e, -1, (p - 1)*(q - 1))
    return d, (e, p*q)

def sign(m, priv_key, public_key):
    h = bytes_to_long(m.encode())
    sig = pow(h, priv_key, public_key[1])
    return sig

def verify(m, sig, public_key):
    h = pow(sig, public_key[0], public_key[1])
    return bytes_to_long(m.encode()) % public_key[1] == h

priv_key, public_key = gen_key()

m = input(f'Welcome to the BlackSmith! Here is our business card: {public_key}. What would you like to craft: ')
if not m.isalnum() or len(m) < 8:
    print("Don't try to scam us!!!")
    exit()

m1 = input('I can give you two samples of our craftmanship. What would you first like a sample of: ')
if not m1.isalnum():
    print("Don't try to scam us!!!")
    exit()

m2 = input('What else: ')
if not m2.isalnum():
    print("Don't try to scam us!!!")
    exit()

if m1 == m or m2 == m or m1 == m2:
    exit()

sig1 = sign(m1, priv_key, public_key)
sig2 = sign(m2, priv_key, public_key)

sig = int(input(f'Here are our samples: ({sig1}, {sig2}). Give us the necessary materials, and we shall deliver what you asked for: '), 16)

if verify(m, sig, public_key):
    print(FLAG)
else:
    print("Don't try to scam us!!!")
```

Solution:
```python
from Crypto.Util.number import *
from sage.all import *
from tqdm import *
from pwn import *
import random
import string

io = remote('127.0.0.01', 50000, level='warning')

io.recvuntil(b': ')
public_key = eval(io.recvuntil(b')'))

cnt = 0
while True:
    print(cnt)
    cnt += 1

    m = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(8))
    m_val = bytes_to_long(m.encode())

    facts = []
    for fact in list(factor(m_val)):
        for _ in range(fact[1]):
            facts.append(fact[0])

    flag = True
    for i in range(1 << len(facts)):
        m1_val = 1
        for j in range(len(facts)):
            if (i & (1 << j)) != 0:
                m1_val *= facts[j]

        m2_val = m_val // m1_val

        try:
            m1 = long_to_bytes(m1_val).decode('ascii')
            m2 = long_to_bytes(m2_val).decode('ascii')
        except:
            continue

        if m1.isalnum() and m2.isalnum():
            flag = False
            break

    if flag is False:
        break

io.recv()
io.sendline(m.encode())

io.recv()
io.sendline(m1.encode())

io.recv()
io.sendline(m2.encode())

io.recvuntil(b': ')
sig1, sig2 = eval(io.recvuntil(b')'))
io.recv()

sig1 = int(sig1)
sig2 = int(sig2)

io.sendline(str(hex((int(sig1)*int(sig2)) % public_key[1]))[2:].encode())

print(io.recvuntil(b'\n').decode())
```

## [Crypto] rsAI

**Creator:** chopingu

**Challenge description:**
```
Artificial intelligence seems to be the solution to every problem nowadays, so 
I have now created a perfectly secure encryption scheme that uses the wonders of AI and RSA. 
E = mc^2 + AI !!!
```

Source:
```python
from Crypto.Util.number import getPrime
from sage.all import *
from sage.symbolic.constants import e as euler_constant

FLAG = 'SSM{REDACTED}'

# RSA + AI = post-quantum secure
class AI:
    def __init__(self, input_size, hidden_sizes, output_size, algebra, activation):
        self.input_size = input_size
        self.hidden_sizes = hidden_sizes
        self.output_size = output_size
        self.algebra = algebra
        self.activation = activation

        # Initialize weights and biases for each layer
        layer_sizes = [input_size] + hidden_sizes + [output_size]
        self.weights = [random_matrix(algebra, layer_sizes[i], layer_sizes[i+1]) for i in range(len(layer_sizes)-1)]
        self.biases = [random_matrix(algebra, 1, layer_sizes[i+1]) for i in range(len(layer_sizes)-1)]

    def forward_pass(self, x):
        for W, b in zip(self.weights, self.biases):
            x = self.activation(x*W + b)

        return x

    def save(self):
        with open('ai_weights', 'w') as f:
            weights = []
            for W in self.weights:
                weights.append(list(W))

            f.write(str(weights))

        with open('ai_biases', 'w') as f:
            biases = []
            for b in self.biases:
                biases.append(list(b))

            f.write(str(biases))

# RSA
e = 0x100
primes = [getPrime(64) for _ in range(20)]
n = prod(primes)
Z = Zmod(n)

# public modulus
with open('modulus', 'w') as f:
    f.write(str(n))

# E[uler] = mc^2 + ai
def euler(x):
    for i in range(len(list(*x))):
        x[0,i] = x[0,i]**(euler_constant**(I*pi) + 2)

    return x

ai = AI(len(FLAG), [len(FLAG) for _ in range(10)], len(FLAG), Z, euler)

# save AI model
ai.save()

# c = m^e
m = matrix(Z, 1, len(FLAG))
for i in range(len(FLAG)):
    m[0,i] = ord(FLAG[i])

c = m
for _ in range(e):
    c = ai.forward_pass(c)

# save encryption
with open('enc_flag', 'w') as f:
    f.write(str(list(c)))
```

Solution:
```python
from sage.all import *
from tqdm import *

with open('modulus', 'r') as f:
    n = int(f.read())
    Z = Zmod(n)
    f.close()

with open('ai_weights', 'r') as f:
    tmp = eval(f.read())
    weights = [matrix(Z, tmp[i]) for i in range(len(tmp))]
    f.close()

with open('ai_biases', 'r') as f:
    tmp = eval(f.read())
    biases = [matrix(Z, tmp[i]) for i in range(len(tmp))]
    f.close()

with open('enc_flag', 'r') as f:
    enc_flag = matrix(Z, eval(f.read()))
    f.close()

e = 0x100
flag_len = len(*enc_flag)

A = prod(weights)
b = zero_matrix(Z, 1, flag_len)
cur = identity_matrix(Z, flag_len)
for i in range(len(biases)-1, -1, -1):
    b += biases[i] * cur
    cur = weights[i] * cur

cur = identity_matrix(Z, flag_len)
for i in tqdm(range(e)):
    enc_flag -= b*cur
    cur *= A

flag = enc_flag * cur**-1
for ch in list(*flag):
    print(chr(ch), end='')

print()
```
