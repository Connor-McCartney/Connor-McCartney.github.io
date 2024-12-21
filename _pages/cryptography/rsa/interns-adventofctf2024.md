---
permalink: /cryptography/rsa/interns-adventofctf2024
title: interns - CyberStudents' advent of ctf 2024
---

<br>


# Challenge

```python
import random
from Crypto.Util.number import getPrime, bytes_to_long, long_to_bytes, inverse
import hashlib

bit_length = 128
p = getPrime(bit_length)
q = getPrime(bit_length)
r = getPrime(bit_length)

N = p * q * r

e1 = 3
e2 = 5

def nested_encrypt(message, e1, e2, N):
    msg_num = bytes_to_long(message)
    step1 = pow(msg_num, e1, N)
    salt = (p + q)  
    step2 = (step1 + salt) % N
    step3 = pow(step2, e2, N)
    mask = int(hashlib.sha256(long_to_bytes(step3)).hexdigest()[:8], 16) 
    ciphertext = step3 ^ mask
    return ciphertext

flag = b"csd{am_i_late_or_am_i_late}"
ciphertext = nested_encrypt(flag, e1, e2, N)
leak_p_bits = bin(p)[-64:]  
leak_q_bits = bin(q)[-64:]
partial_salt = (p + q) % 100000  

with open("public.txt", "w") as f:
    f.write(f"N = {N}\nLeaked bits of p = {leak_p_bits}\nLeaked bits of q = {leak_q_bits}\n")
    f.write(f"Partial salt (p + q mod 100000) = {partial_salt}\n")

with open("ciphertext.txt", "w") as f:
    f.write(str(ciphertext))

print("Try breaking me :)")
```

<br>

```
N = 20829189282001863372322428196733308195464709019397028562940874561583326274287129648306568901830962480022928679678123
a lil p = 1110100110011011101000100001101100001010111001100001011001101111
a lil q = 1011110111011111011101010111111010011010110011110011010100111111
salty= 18766
```

```
14148786803331853127777889559896138396417219981773502601578745985604370779076393473723769040986523787622227351205298
```

<br>

# Solve

First brute the mask, it's less than 32 bits. 

```python
from tqdm import trange
from Crypto.Util.number import *
from hashlib import sha256

ciphertext = 14148786803331853127777889559896138396417219981773502601578745985604370779076393473723769040986523787622227351205298

for mask in trange(2**32):
    step3 = mask ^ ciphertext
    if mask == int(sha256(long_to_bytes(step3)).hexdigest()[:8], 16):
        print(mask)
```

You can get a small speedup with rust:

```rust
use rug::ops::BitXorFrom;
use rug::Integer;
use sha256::digest;
use indicatif::ProgressBar;


fn int_to_bytes(mut n: Integer) -> Vec<u8> {
    let mut ret = vec![];
    while n > 0 {
        let x = n.mod_u(256) as u8;
        ret.push(x);
        n = n / 256;
    }
    ret.reverse();
    return ret;
}

fn main() {
    let ciphertext = Integer::from_str_radix("14148786803331853127777889559896138396417219981773502601578745985604370779076393473723769040986523787622227351205298", 10).unwrap();

    let max: u64 = 4294967296; // 2**32
    let bar = ProgressBar::new(max);
    for mask in 0..max {
        bar.inc(1);
        let mut step3 = Integer::from(mask);
        step3.bitxor_from(ciphertext.clone());
        let hash = &digest(int_to_bytes(step3))[..8];
        let mask_hex = format!("{:x}", mask);
        if hash == mask_hex {
            println!("mask = {}", hash);
        }
    }
}
```

<br>

There are multiple possibilities, I found these:

```python
possible_masks = [3306955427, 2186477323, 2523079120]
for mask in possible_masks:
    step3 = mask ^ ciphertext
    print(mask == int(sha256(long_to_bytes(step3)).hexdigest()[:8], 16))
```
