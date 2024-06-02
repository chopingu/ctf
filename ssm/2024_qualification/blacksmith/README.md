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
