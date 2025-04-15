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
