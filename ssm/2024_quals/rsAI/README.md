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
