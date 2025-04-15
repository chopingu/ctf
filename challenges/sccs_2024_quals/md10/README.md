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
