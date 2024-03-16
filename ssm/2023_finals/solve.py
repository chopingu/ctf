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
s=[s1, s2, s3, s4]

r=remote('35.217.9.126', 50000, ssl=True)

for i in range(4):
    r.sendlineafter(b'Leave\n', b'1')
    r.sendlineafter(b'sell?\n', s[i].encode()) 

r.sendlineafter(b'Leave\n', b'2')
r.sendlineafter(b'buy?\n', b'Flag')
r.recv()
print(r.recv()[28:-1].decode())
