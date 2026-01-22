+++
date = 2026-01-21
description ="KnightCTF 2026 - Reversing50 - E4sy P3asy"
title = "KnightCTF 2026 - Reversing50 - E4sy P3asy"
[taxonomies]
tags = ["ctf", "reversing", "ghidra", "binaryninja"]
+++

## Task

```
## E4sy P3asy

### 50 Points

Author

NomanProdhan

An easy RE...

Flag Format : KCTF{flag}
```

File: https://drive.google.com/file/d/1WqG5W-UkDFf4pAeRf5tdTs9ClN1UD1K6/view

It's and elf stripped file.

```shellsession
~/Vault/isec/ctf/knight2k26  ✓ $ file E4sy_P3asy.ks
E4sy_P3asy.ks: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=ccaa420882d2b8eb1bf3a2cc82b527aa19911512, for GNU/Linux 4.4.0, stripped

```

It has some hashes in strings which may be useful later:

```shellsession
~/Vault/isec/ctf/knight2k26  ✓ $ strings E4sy_P3asy.ks
...
flag>
GoogleCTF{
%s%zu%c
Try again!
FLAG{
KCTF{
Good job! You got it!
========================================
   E4sy P3asy - KnightCTF 2026
[*] Enter the flag to prove your worth!
[!] Interesting... but that's a decoy flag from a different universe.
[!] You're in KnightCTF, not GoogleCTF :)
[?] Format looks suspicious... but not quite.
781011edfb2127ee5ff82b06bb1d2959
4cf891e0ddadbcaae8e8c2dc8bb15ea0
d06d0cbe140d0a1de7410b0b888f22b4
d44c9a9b9f9d1c28d0904d6a2ee3e109
e20ab37bee9d2a1f9ca3d914b0e98f09
d0beea4ce1c12190db64d10a82b96ef8
ac87da74d381d253820bcf4e5f19fcea
ce3f3a34a04ba5e5142f5db272b6cb1f
13843aca227ef709694bbfe4e5a32203
ca19a4c4eb435cb44d74c1e589e51a10
19edec8e46bdf97e3018569c0a60baa3
972e078458ce3cb6e32f795ff4972718
071824f6039981e9c57725453e005beb
66cd6098426b0e69e30e7fa360310728
f78d152df5d277d0ab7d25fb7d1841f3
dba3a36431c4aaf593566f7421abaa22
8820bbdad85ebee06632c379231cfb6b
722bc7cde7d548b81c5996519e1b0f0f
c2862c390c830eb3c740ade576d64773
94da978fe383b341f9588f9bab246774
bea3bb724dbd1704cf45aea8e73c01e1
ade2289739760fa27fd4f7d4ffbc722d
3cd0538114fe416b32cdd814e2ee57b3
8af7f29b21564b87336ed4e4cdfb1a20
4d3f509284784ab67818b13e74fd5ebe
5a45666e1387ff739eb470f840532099
c96997e23323e502d5d0b07d24a68d50
efb388057adc3fe734d8b6ffb2bdd1e1
6df2aaf58e39f89d7a31a72e19e0efbf
9bbd077d3df7faedfd22fae85043d6c0
dc72837ea6ba778eebbd0401a35182f4
efa0bc7c5da3545ba15548b4b85eaf76
1c36dbad9144b1e1d23ddecb5d4df3e9
980663d212aed1ba720f7735873fa73c
9df295c8874bcac93c98babe78b9c946
2672e4d30c7da0d30749f09bc1b1eefa
;*3$"
GCC: (GNU) 15.2.1 20251112
.....
```

Also, regarding those hashes, md5 is also mentioned in strings:
```c
EVP_MD_CTX_new
EVP_md5
EVP_DigestUpdate
EVP_DigestFinal_ex
```
### Reversing

This binary does the following, in order:

1.  Reads user input (flag)
2. Extracts part of solution from KCTF{...}
3. Using each character from submitted user flag and salt "KnightCTF_2026_s@lt" it builds a string in format **salt + index + char **

```c
snprintf(&var_2c8, 0x80, "%s%zu%c", var_358, i, (&var_148)[i])
sub_401660(&var_2c8, strlen(&var_2c8), &var_338)
if (strcmp(&var_338, (&data_403ca0)[i]) != 0)
    fail

```
4.  Hashes it with MD5 and compares it to the hash table which we saw in strings
5. If all hashes are ok, profit!



````asm
00401140    int64_t sub_401140()

00401151        void* fsbase
00401151        int64_t rdi = *(fsbase + 0x28)
00401171        puts("========================================")
0040117d        puts("   E4sy P3asy - KnightCTF 2026")
00401189        puts("========================================")
00401195        puts("[*] Enter the flag to prove your worth!")
004011a1        puts(&data_402009[6])
004011af        printf("flag> ")
004011cb        void var_248
004011cb        
004011cb        if (fgets(&var_248, 0x100, stdin) != 0)
004011d4            int64_t rax_2 = strlen(&var_248)
004011dc            int32_t* var_358
004011dc            
004011dc            if (rax_2 != 0)
004011e3                char* rax_3 = &var_358 + rax_2 + 0x10f
004011e3                
0040120d                do
0040120f                    char rdx_1 = *rax_3
0040120f                    
0040121a                    if (rdx_1 != 0xa && rdx_1 != 0xd)
0040121a                        break
0040121a                    
00401200                    *rax_3 = 0
00401206                    rax_3 -= 1
0040120d                while (1 - &var_248 != neg.q(rax_3))
0040120d            
00401235            char var_148
00401235            sub_401660(&var_248, strlen(&var_248), &var_148)
0040124b            char var_147
0040124b            
0040124b            if ((var_148 ^ var_147) == 0x5a)
0040132b                int32_t var_33c_1 = 1
0040133c                int32_t var_33c_2 = 0x1336
0040133c            
00401262            void var_338
00401262            int32_t var_308
00401262            void var_2c8
00401262            
00401262            if (sub_401760(&var_248, "GoogleCTF{") == 0)
00401293            label_401293:
00401293                int32_t rax_9 = sub_401760(&var_248, "CTF{")
0040129a                int32_t rax_10
0040129a                
0040129a                if (rax_9 == 0)
004012aa                    rax_10 = sub_401760(&var_248, "FLAG{")
004012aa                
004012b4                if (rax_9 != 0 || rax_10 != 0)
0040134c                    puts("[?] Format looks suspicious... but not quite.")
00401358                    puts("Try again!")
004012b4                else if (sub_401760(&var_248, "KCTF{") == 0)
004012f9                labelid_3:
004012f9                    puts("Try again!")
004012cb                else if (sub_4017a0(&var_248) == 0)
004012f9                label_4012f9:
004012f9                    puts("Try again!")
004012d7                else
004012dc                    int64_t rax_13 = strlen(&var_248)
004012dc                    
004012ec                    if (rax_13 - 6 u<= 0xff)
00401476                        void var_243
00401476                        __builtin_memcpy(dest: &var_148, src: &var_243, count: rax_13 - 6)
0040147d                        char var_14e[0x6]
0040147d                        var_14e[rax_13] = 0
0040148d                        var_358 = &var_308
00401491                        int64_t rcx_5
00401491                        int64_t rdi_17
00401491                        rdi_17, rcx_5 = __memfill_u32(&var_308, rax_10, 0x10)
00401493                        __builtin_strncpy(dest: &var_308, src: "KnightCTF_2026_s@lt", 
00401493                            count: 0x13)
00401493                        
004014c2                        if (rax_13 != 0x1d)
004012f9                        label_4012f9_1:
004012f9                            puts("Try again!")
004014c2                        else
004014cf                            int64_t i = 0
004014d9                            char const* const var_350_2 = "%s%zu%c"
004014d9                            
004014e8                            do
0040150b                                snprintf(&var_2c8, 0x80, var_350_2, var_358, i, 
0040150b                                    zx.q(sx.d((&var_148)[i])))
0040152d                                sub_401660(&var_2c8, strlen(&var_2c8), &var_338)
0040152d                                
00401542                                if (strcmp(&var_338, (&data_403ca0)[i]) != 0)
00401542                                    goto label_4012f9_2
00401542                                
004014e0                                i += 1
004014e8                            while (i != 0x17)
004014e8                            
00401550                            puts("Good job! You got it!")
004012ec                    else
004012f9                    label_4012f9_2:
004012f9                        puts("Try again!")
00401262            else
0040126e                if (sub_4017a0(&var_248) == 0)
0040126e                    goto label_401293
0040126e                
00401273                int64_t rax_8 = strlen(&var_248)
00401273                
00401283                if (rax_8 - 0xb u> 0xff)
00401283                    goto label_401293
00401283                
0040136d                void var_23e
0040136d                __builtin_memcpy(dest: &var_148, src: &var_23e, count: rax_8 - 0xb)
00401374                char var_153[0x5]
00401374                var_153[rax_8] = 0
00401383                var_358 = &var_308
00401387                __builtin_memset(dest: &var_308, ch: 0, count: 0x40)
00401389                __builtin_strcpy(dest: &var_308, src: "G00gleCTF_s@lt_2026")
00401389                
004013ba                if (rax_8 != 0x18)
004013ba                    goto label_401293
004013ba                
004013c7                int64_t i_1 = 0
004013d1                char const* const var_350_1 = "%s%zu%c"
004013d1                
0040143d                do
004013f7                    snprintf(&var_2c8, 0x80, var_350_1, var_358, i_1, 
004013f7                        zx.q(sx.d((&var_148)[i_1])))
00401419                    sub_401660(&var_2c8, strlen(&var_2c8), &var_338)
00401419                    
0040142f                    if (strcmp(&var_338, (&data_403d60)[i_1]) != 0)
0040142f                        goto label_401293
0040142f                    
00401435                    i_1 += 1
0040143d                while (i_1 != 0xd)
0040143d                
00401446                puts("
00401446                    [!] Interesting... but that's a decoy flag from a different universe.")
00401452                puts("[!] You're in KnightCTF, not GoogleCTF :)")
0040145e                puts("Try again!")
0040145e        
00401308        *(fsbase + 0x28)
00401308        
00401311        if (rdi == *(fsbase + 0x28))
0040132a            return 0
0040132a        
0040155a        int64_t rdx_9
0040155a        int64_t rsi_7
0040155a        int64_t rdi_22
0040155a        rdx_9, rsi_7, rdi_22 = __stack_chk_fail()
0040155f        noreturn _start(rdi_22, rsi_7, rdx_9) __tailcall

```````

## Solution

I wrote a python script which takes our salt and index and brute-forces each char until it matches hash from the hash table.
The binary checks:

```python
expected = [
  MD5("KnightCTF_2026_s@lt0" + flag[0]),
  MD5("KnightCTF_2026_s@lt1" + flag[1]),
  ...
]
```

The plan is following:
```
for each position/index:
    try all ASCII chars
    find the one that matches
```

Here is the python script implementation:
```python
import hashlib

targets = [
"781011edfb2127ee5ff82b06bb1d2959",
"4cf891e0ddadbcaae8e8c2dc8bb15ea0",
"d06d0cbe140d0a1de7410b0b888f22b4",
"d44c9a9b9f9d1c28d0904d6a2ee3e109",
"e20ab37bee9d2a1f9ca3d914b0e98f09",
"d0beea4ce1c12190db64d10a82b96ef8",
"ac87da74d381d253820bcf4e5f19fcea",
"ce3f3a34a04ba5e5142f5db272b6cb1f",
"13843aca227ef709694bbfe4e5a32203",
"ca19a4c4eb435cb44d74c1e589e51a10",
"19edec8e46bdf97e3018569c0a60baa3",
"972e078458ce3cb6e32f795ff4972718",
"071824f6039981e9c57725453e005beb",
"66cd6098426b0e69e30e7fa360310728",
"f78d152df5d277d0ab7d25fb7d1841f3",
"dba3a36431c4aaf593566f7421abaa22",
"8820bbdad85ebee06632c379231cfb6b",
"722bc7cde7d548b81c5996519e1b0f0f",
"c2862c390c830eb3c740ade576d64773",
"94da978fe383b341f9588f9bab246774",
"bea3bb724dbd1704cf45aea8e73c01e1",
"ade2289739760fa27fd4f7d4ffbc722d",
"3cd0538114fe416b32cdd814e2ee57b3",
]

salt = "KnightCTF_2026_s@lt"
flag = ""

for i in range(len(targets)):
    for c in range(32, 127):
        s = f"{salt}{i}{chr(c)}".encode()
        h = hashlib.md5(s).hexdigest()
        if h == targets[i]:
            flag += chr(c)
            print(i, chr(c))
            break

print("KCTF{" + flag + "}")

```


Running the python script above successfully brute-forces the flag:
```console
~/Vault/isec/ctf/knight2k26  ✓ $ python crack3.py
0 _
1 L
2 0
3 T
4 S
5 _
6 o
7 F
8 _
9 b
10 R
11 u
12 T
13 E
14 _
15 f
16 o
17 R
18 C
19 E
20 _
21 :
22 P
KCTF{_L0TS_oF_bRuTE_foRCE_:P}
~/Vault/isec/ctf/knight2k26  ✓ $ ./E4sy_P3asy.ks
========================================
   E4sy P3asy - KnightCTF 2026
========================================
[*] Enter the flag to prove your worth!

flag> KCTF{_L0TS_oF_bRuTE_foRCE_:P}
Good job! You got it!

```

Flag: **KCTF{_L0TS_oF_bRuTE_foRCE_:P}**

![](/images/14c27ddac401a76eff2848bd6f809604.png)