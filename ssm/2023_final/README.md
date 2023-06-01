# Swedish Olympiad in IT Security 2023 Final

## [Crypto] Chalmer's Store

**Creator:** Joshua Andersson

**Challenge description:**
```
There are a lot of goodies to buy from Chalmer's Store
```

We are given a C++ file `service.cpp` and the socket address to a server which runs that file. The C++ file takes an item in the form of a string, consisting of lowercase letters, and hashes it using a custom hash that consists of several rolling hashes. 

```cpp
unsigned long long magic[] = { 4404 ^ 3214, 25954 ^ 3214, 17763 ^ 3124 };

unsigned long long hashonce(const std::string& s, unsigned long long b)
{
	unsigned long long h = 0;
	unsigned long long m = 1;
	for (auto c : s)
	{
		h = (h + m * c) % 0x1FFFF7;
		m = m * b % 0x1FFFF7;
	}
	return h;
}

unsigned long long powerhash(const std::string& s)
{
	return hashonce(s, magic[0]) + (hashonce(s, magic[1]) << 21) + (hashonce(s, magic[2]) << 42);
}
```

Each new hash created from an item is assigned a value by Chalmer's Store and we are able to earn that value in coins by selling the item. By earning a total of 1000 coins it is possible to buy the flag from the store. However each new hash created is assigned a value in such a way, that the sum of them converges to a value just below 1000.

```cpp
int getprice(const std::string& s)
{
	unsigned long long snowflake = powerhash(s);
	if (values.find(snowflake)!=values.end())
	{
		return values[snowflake];
	}
	return values[snowflake] = int(1000 * pow(0.67, (double)values.size()));
}
```

What about already created hashes then? It is not possible to sell a particular item twice, but if the hash of a new item already has a value assigned to it, we earn that value in coins, as seen above. Therefore, by finding a collision in the custom hash used by the store, we are able to earn 1000 coins and buy the flag. Let us take a closer look into the custom hash `powerhash` that is used to store values. 

```cpp
unsigned long long hashonce(const std::string& s, unsigned long long b)
{
	unsigned long long h = 0;
	unsigned long long m = 1;
	for (auto c : s)
	{
		h = (h + m * c) % 0x1FFFF7;
		m = m * b % 0x1FFFF7;
	}
	return h;
}

unsigned long long powerhash(const std::string& s)
{
	return hashonce(s, magic[0]) + (hashonce(s, magic[1]) << 21) + (hashonce(s, magic[2]) << 42);
}
```

Notice how `hashonce` creates a value modulo, $p$,  `0x1FFFF7` which is less than $2^{21}$ and $2^{42}$. This leads to the custom hash simply being a concatenation of the three rolling hashes `hashonce(s, magic[0])`, `hashonce(s, magic[1])` and `hashonce(s, magic[2])`. Further, if we want to find two strings $s_{0}$ and $s_{1}$ of length $n$, such that $\text{powerhash}(s_{0})=\text{powerhash}(s_{1})$, then the following should be true:


```math
\text{hashonce}(s_{0}, \text{magic}[0])=\text{hashonce}(s_{1}, \text{magic}[0])
```

```math
\text{hashonce}(s_{0}, \text{magic}[1])=\text{hashonce}(s_{1}, \text{magic}[1])
```

```math
\text{hashonce}(s_{0}, \text{magic}[2])=\text{hashonce}(s_{1}, \text{magic}[2])
```

$$
\Leftrightarrow
$$

```math
\sum\limits_{i=0}^{n-1} \: (\text{magic}[0]^i \; \text{mod} \; p) \cdot s_{0}[i] \equiv \sum\limits_{i=0}^{n} \: (\text{magic}[0]^i \; \text{mod} \; p) \cdot s_{1}[i] \; (\text{mod} \; p)
```

```math
\sum\limits_{i=0}^{n-1} \: (\text{magic}[1]^i \; \text{mod} \; p) \cdot s_{0}[i] \equiv \sum\limits_{i=0}^{n} \: (\text{magic}[1]^i \; \text{mod} \; p) \cdot s_{1}[i] \; (\text{mod} \; p)
```

```math
\sum\limits_{i=0}^{n-1} \: (\text{magic}[2]^i \; \text{mod} \; p) \cdot s_{0}[i] \equiv \sum\limits_{i=0}^{n} \: (\text{magic}[2]^i \; \text{mod} \; p) \cdot s_{1}[i] \; (\text{mod} \; p)
```

$$
\Leftrightarrow
$$

```math
\sum\limits_{i=0}^{n-1} \; (\text{magic}[0]^i \; \text{mod} \; p) \cdot (s_{0}[i]-s_{1}[i]) \equiv 0 \; (\text{mod} \; p)
```

```math
\sum\limits_{i=0}^{n-1} \; (\text{magic}[1]^i \; \text{mod} \; p) \cdot (s_{0}[i]-s_{1}[i]) \equiv 0 \; (\text{mod} \; p)
```

```math
\sum\limits_{i=0}^{n-1} \; (\text{magic}[2]^i \; \text{mod} \; p) \cdot (s_{0}[i]-s_{1}[i]) \equiv 0 \; (\text{mod} \; p)
```

Due to the charset requirement, the difference $(s_{0}[i]-s_{1}[i])$ can only be between -25 and 25. Therefore, we seek a linear combination of the terms $`\text{magic}[k]^{i} \; (\text{mod} \; p), \; k \in {0, 1, 2}`$ with small coefficients, $(s_{0}[i]-s_{1}[i])$, and which sums to zero. Normally, this would have been as hard as finding solutions to a system of linear congruences, but since we have constraints on the coefficients it is solvable. We proceed by creating the following matrix:

```math
L: M=\begin{pmatrix}
    10^5\cdot\text{magic}[0]^0 & 10^5\cdot\text{magic}[1]^0 & 10^5\cdot\text{magic}[2]^0 & 1 & 0 & ... & 0 \\
    10^5\cdot\text{magic}[0]^1 & 10^5\cdot\text{magic}[1]^1 & 10^5\cdot\text{magic}[2]^1 & 0 & 1 & ... & 0 \\
    10^5\cdot\text{magic}[0]^2 & 10^5\cdot\text{magic}[1]^2 & 10^5\cdot\text{magic}[2]^2 & 0 & 0 & ... & 0 \\
                               &                     ... & ... & \\
    10^5\cdot\text{magic}[0]^n & 10^5\cdot\text{magic}[1]^n & 10^5\cdot\text{magic}[2]^n & 0 & 0 & ... & 1 \\
    10^5 \cdot p & 0 & 0 & ... \\
    0 & 10^5 \cdot p & 0 & ... \\
    0 & 0 & 10^5 \cdot p & ... \\

\end{pmatrix}
```

```math
\therefore \; 
w=\begin{pmatrix} 0 & 0 & 0 & (s_{0}[0]-s_{1}[0]) & (s_{0}[1]-s_{1}[1]) & (s_{0}[2]-s_{1}[2]) & ... \end{pmatrix} \in L 
```

The rows in $M$ form the basis of a lattice and there is a small vector $w$ in it which satisfies our linear congruences while giving us the values of the coefficients. Since we need the linear combination to be exactly zero, it is important to multiply each term with a large factor to penalize non-zero sums. Otherwise there might other small vectors where the linear combinations are not zero. We can find the vector $w$ by finding a good reduction of $M$, filling $s_{0}$ with the letter 'a' and setting each character in $s_{1}$ according to the values of the coefficients $(s_{0}[i]-s_{1}[i]), \; 0 \leq i \leq n-1$. Potentially, it might also be necessary to swap the corresponding letters in $s_{0}$ and $s_{1}$ if the coefficient is negative. Following is the solve script and the flag found is `SSM{r4nd0m1z3_y0ur_b4s3}`: 

```python
from sage.all import *
from pwn import *

magic_p=[(7610, 0x1FFFF7), (27116, 0x1FFFF7), (18775, 0x1FFFF7)]
magics=[magic for magic,p in magic_p]
ps=[p for magic,p in magic_p]

def collision(n):
    m=matrix(ZZ, n, n)
    for i in range(n):
        for j, magic, p in zip(range(len(magic_p)), magics, ps):
            m[i,j]=pow(magic, i, p);

    M=matrix(ZZ, n+len(magic_p), n+len(magic_p))
    M.set_block(0, 0, 100000*m)
    M.set_block(n, 0, 100000*diagonal_matrix(ps))
    M.set_block(0, len(magic_p), identity_matrix(n))

    for w in M.LLL():
        mx_coeff=max(abs(v) for v in w[len(magic_p):])
        if set(w[:len(magic_p)])=={0} and mx_coeff<=25:
            s1=[0]*n
            s2=[0]*n
            for i,v in enumerate(w[len(magic_p):]):
                a=ord('a')
                b=a+abs(v)
                if v>0:
                    a,b=b,a
                s1[i]=a
                s2[i]=b

            s1=''.join(map(chr, s1))
            s2=''.join(map(chr, s2))
            return s1,s2

s1,s2=collision(20)
s3,s4=collision(30)

r=remote('35.217.9.126', 50000, ssl=True)

r.recvuntil(b'Leave\n')
r.sendline(b'1')
r.recvuntil(b'sell?\n')
r.sendline(s1.encode())
r.recvuntil(b'Leave\n')
r.sendline(b'1')
r.recvuntil(b'sell?\n')
r.sendline(s2.encode())
r.recvuntil(b'Leave\n')
r.sendline(b'1')
r.recvuntil(b'sell?\n')
r.sendline(s3.encode())
r.recvuntil(b'Leave\n')
r.sendline(b'1')
r.recvuntil(b'sell?\n')
r.sendline(s4.encode())
r.recvuntil(b'Leave\n')
r.sendline(b'2')
r.recvuntil(b'buy?\n')
r.sendline(b'Flag')
r.recv()
print(r.recv()[28:-1].decode())
```
