---
permalink: /cryptography/rsa/VULPIX-squeamishossifrage
title: VULPIX - squeamishossifrage
---

<br>

[Challenge](https://github.com/zerosumsecurity/squeamishossifrage/tree/main/VULPIX)

<br>

Solve:

```python
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES 
import heapq

with open("SPARSERSA.crt", "rb") as f:
    key = RSA.import_key(f.read())

n = key.n
e = key.e

#https://github.com/google/google-ctf/blob/master/2020/quals/crypto-yafm/solve.py
def CheckLowHammingWeight(n, cutoff = 2500, maxsteps = 10**6):
  """Tries to factor n assuming that the factors have a low Hamming weight.


  This algorithm is loosly based on crackpot claims that the bit
  patterns for the prime factors can be derived from the bit pattern
  of the product. This doesn't work for general integers, but may
  work if n is the product of two factors with a small Hamming weight.

  Args:
      n: the modulus to test
      cutoff: the number or steps after which the search is abandoned if
           no promissing branch has been found. The default of 2500 means that
           the function takes about 100 ms when n is not a product of factors
           with a low Hamming weight.
      maxsteps: an upper bound on the maximal number of steps. The default
           value 10**6 means that the search spends about 20 seconds before
           giving up. A value of 10**7 is the largest value tested with
           64 GB of memory.
  Returns:
      A tuple (weak, factors), where the value weak is True if the modulus
      is (probably) weak, and a list of factors that were found.
      The test can fail even if no factors were found. This happens when
      the search finds a partial factorization with unusually low
      Hamming weight. E.g., the following cases can be detected without
      finding a factorization:
         * the Hamming weight of the factors is close to the bound that
           can be factored. E.g. products of two 1024-bit primes with
           Hamming weight 96 often require 10**7 or more steps to factor.
         * only the most significant bits of the factors have a small
           Hamming weight. The key may still be weak because other methods
           such as Coppersmith may be used to find the least significant bits.
         * the primes are not of equal size. The search will still find
           partial factorizations with low Hamming weight, but fail to factor n.
         * the search spends a lot of time with false positives. The product
           of two factors of very low Hamming weight often has other partial
           factorizations with low Hamming weight.
  """

  def Heuristic(hamming_weight, rem_size):
    """The heuristic used for the search.

    The heuristc (in particular the factor 5) has been determined
    experimentally. Using a factor 5 in this heuristic allows to factor
    some 2048 bit products where each of the 1024-bit factors has a Hamming
    weight 96. The factor 5 has the property that the heuristic of correct
    guesses are expected to slowly decrease with more bits of the factors
    guessed, while the heuristic of incorrect guesses are slowly increasing.

    Args:
      hamming_weight: the Hamming weight of the partial factors p0 and q0
      rem_size: (n - (p0 << bit) * (q0 << bit)).bit_length()

    Returns:
      the heuristic. Smaller is better.
    """
    return rem_size + 5 * hamming_weight

  # A heap containing partial factorizations.
  # This heap is being used by the function Push below.
  # Elements in the heap are quintuples (v, hw, bit, p0, q0) where:
  #   v: is the result of the function Heuristic above.
  #   hw: is the sum of the Hamming weights of p0 and q0.
  #   bit: is the number of missing bits in p0 and q0.
  #   p0: a guess for the msbs of p, i.e., the value p >> bit.
  #   q0: a guess for the msbs of q, i.e., the value q >> bit.
  heap = []

  def Push(p0, q0, hw, bit, rem_size):
    """Computes the heuristic and pushes the values into the priority queue.

    Args:
      p0: a partial factor.
      q0: a partial factor.
      hw: the sum of the Hamming weights of p0 and q0
      bit: the number of bits that are still to guess.
      rem_size: (n - (p << bit) * (q << bit)).bit_length()
    """
    # invariants:
    # assert (p0 << bit) * (q0 << bit) <= n < ((p0+1) << bit) * ((q0+1) << bit)

    # The algorithm looks for a factorization where p <= q.
    if p0 <= q0:
      v = rem_size + 5 * hw
      heapq.heappush(heap, (v, hw, bit, p0, q0))

  # There are two thresholds for the heurisitic.
  # If no value of the heuristic smaller than threshold_cutoff is found then
  # the search is stopped after cutoff steps. Hence checking a correctly
  # generated RSA key will very likely stop after cutoff steps.
  # If a small value or the heuristic is found then search will continue until
  # a factorization is found or maxsteps steps were made. If at this point
  # the minimal value for the heuristic is smaller or equal to threshold_weak
  # (and no factorzation was found) then the RSA key is considered to be
  # potentially weak. Such keys may need to be analyzed further.
  threshold_cutoff = n.bit_length()
  threshold_weak = n.bit_length() - 12

  psize = (n.bit_length() + 1) // 2
  steps = 0
  remainder = n - (1 << (2 * (psize - 1)))
  Push(1, 1, 2, psize - 1, remainder.bit_length())
  # smallest value for the heuristic
  minv = Heuristic(2, remainder.bit_length())
  while steps < maxsteps and heap:
    steps += 1
    if steps == cutoff:
      if minv >= threshold_cutoff:
        break

    v, hw, bit, p, q = heapq.heappop(heap)
    if v < minv:
      minv = v
    # Doing computations on the msbs only saves 40% CPU time.
    while bit >= 1:
      p <<= 1
      q <<= 1
      bit -= 1
      n0 = n >> (2 * bit)
      for dp, dq in ((0, 1), (1, 0), (1, 1)):
        # min = pq + p, pq + q, pq + p + q + 1
        p0 = p + dp
        q0 = q + dq
        # The algorithm guesses at this point that the factors of n are
        # in the range [p0 << bit, (p0 + 1) << bit]
        # and the range [p1 << bit, (p1 + 1) << bit].
        rem0 = n0 - p0 * q0
        if rem0 < 0:
          break
        if bit:
          if rem0 <= p0 + q0:
            rem_size = rem0.bit_length() + 2 * bit
            Push(p0, q0, hw + dp + dq, bit, rem_size)
        else:
          if rem0 == 0:
            return True, [p0, q0]
      else:
        if rem0 > 0:
          break
  potentially_weak = minv <= threshold_weak
  return potentially_weak, []

res, factors = CheckLowHammingWeight(n)
if res and factors:
    p, q = factors
    assert p * q == n
    print(f"{p = }")
    print(f"{q = }")

 
# openssl smime -in flag.encrypted -pk7out -out flag.pk7
# openssl pkcs7 -in flag.pk7 -print
enc_key = 0x5f529c47a63e1447f95ce19263e59a2696dd661030bf2218bcea8a1cff4dc75328aab000db9ceca904b831ff7388ef3b3c97cb72dedbc0afecfa0d48403403f0c61591b08b36da8fb30653d126077e86f16f35f5e372b557a046bbc4b6f8cba7a4bcd1ed21d6071d9d42d377f50c80a79c3a757596455d29bce5188d7139a53d
enc_data = '58a36ff32aab152227245bcf96b4cd0128c8be8fb13f8c07abafa124c17b444d904a8ba4a978667e48bc0bb3bee9fe9b'
iv = '2e89748834a486de139c6bc25e604c79'

d = pow(e, -1, (p-1)*(q-1))
key = bytes.fromhex(hex(pow(enc_key, d, n))[-64:])
enc_data = bytes.fromhex(enc_data)
iv = bytes.fromhex(iv)

cipher = AES.new(key, AES.MODE_CBC, iv)  
print(cipher.decrypt(enc_data))
# so{8175d69b57c9fac9e9223a9829b19beb}
```
