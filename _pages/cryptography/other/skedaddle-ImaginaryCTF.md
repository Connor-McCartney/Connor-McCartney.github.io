---
permalink: /cryptography/other/skedaddle-ImaginaryCTF
title: skedaddle - Imaginary CTF
---

<br>


Challenge:

```c
#include <stdint.h>
#include <stdio.h>

uint64_t fmix64(uint64_t k) {
    k ^= k >> 33;
    k *= 0xff51afd7ed558ccd;
    k ^= k >> 33;
    k *= 0xc4ceb9fe1a85ec53;
    k ^= k >> 33;
    return k;
}

int main() {
    uint64_t i = 1;
    while (fmix64(i) != i) ++i;
    printf("ictf{ %lu }\n", i);
}
```

<br>


Solve:



```python
def f(k):
    k2 = k ^ (k>>33)
    k3 = k2 * 0xff51afd7ed558ccd % 2**64
    k4 = k3 ^ (k3>>33)
    # we'll calculate lsb of k4 at this point
    k5 = k4 * 0xc4ceb9fe1a85ec53 % 2**64
    k6 = k5 ^ (k5>>33)
    return k6
```

<br>

```python
def f(k):
    k2 = k ^ (k>>33)
    k3 = k2 * 0xff51afd7ed558ccd % 2**64
    k4 = k3 ^ (k3>>33) # midpoint
    k5 = k4 * 0xc4ceb9fe1a85ec53 % 2**64
    k6 = k5 ^ (k5>>33)

    k2_lsb = k2 % 2**33
    k4_lsb = k4 % 2**33
    k5_lsb = k5 % 2**33

    # from the top:
    assert k4_lsb == ((k2_lsb * 0xff51afd7ed558ccd) ^ (k3>>33)) % 2**33

    # from the bottom:
    assert k4_lsb == k5_lsb * pow(0xc4ceb9fe1a85ec53, -1, 2**64) % 2**33

    assert k5_lsb == k2_lsb
    assert k3 >> 33 == k4 >> 33

    # rearrange bottom:
    assert k5_lsb == k4_lsb * 0xc4ceb9fe1a85ec53 % 2**33

    # sub into top:
    assert k4_lsb == ((k4_lsb * 0xc4ceb9fe1a85ec53 * 0xff51afd7ed558ccd) ^ (k4>>33)) % 2**33
    assert (k4>>33) == k4_lsb ^ (k4_lsb * 0xc4ceb9fe1a85ec53 * 0xff51afd7ed558ccd % 2**33)
    assert (k4>>33) == k4_lsb ^ (k4_lsb * 0xc4ceb9fe1a85ec53 * 0xff51afd7ed558ccd) & 0x1ffffffff



f(13621417624426829092)
```


So you can brute k4_lsb (2^33) which gives you k4_msb


<br>

```c
#include <stdio.h>
#include <stdint.h>

int main() {
    for (uint64_t k4_lsb=1; k4_lsb<(1UL<<33); k4_lsb++) {
        uint64_t k4_msb = (k4_lsb ^ (k4_lsb*0xc4ceb9fe1a85ec53*0xff51afd7ed558ccd)) & 0x1ffffffff;
        uint64_t k4 = k4_msb * (1UL<<33) + k4_lsb;

        uint64_t k5 = k4 * 0xc4ceb9fe1a85ec53;
        uint64_t k6 = k5 ^ (k5 >> 33);

        uint64_t k3 = k4 ^ (k4 >> 33);
        uint64_t k2 = k3 * 5725274745694666757;
        uint64_t k1 = k2 ^ (k2 >> 33);

        if (k1 == k6) {
            printf("ictf{ %lu }\n", k1);
        }
    }
}
```

<br>



flag: `ictf{13621417624426829092}`








<br>

<br>

<br>

<br>

<br>

<br>

<br>

<br>

<br>

<br>

<br>

<br>

<br>

<br>

<br>

<br>

<br>

<br>

<br>

<br>

<br>

<br>

<br>

<br>

---

<br>

<br>

<br>


# skedaddle revenge

Challenge:

```python
#!/usr/local/bin/python3
def fmix128(k):
    k ^= k >> 65
    k *= 0xff51afd7ed558ccdff51afd7ed558ccd
    k &= 0xffffffffffffffffffffffffffffffff
    k ^= k >> 65
    k *= 0xc4ceb9fe1a85ec53c4ceb9fe1a85ec53
    k &= 0xffffffffffffffffffffffffffffffff
    k ^= k >> 65
    return k

k = int(input('k: '), 0)
if 0 < k < 2**128 and k == fmix128(k):
    print('ictf{REDACTED}')
else:
    print('WRONG')
```

<br>

Solve:




<br>

First take a look at an observation from the previous chall, you can write 

```python
k = 13621417624426829092

k2 = k ^ (k>>33)
k3 = k2 * 0xff51afd7ed558ccd % 2**64
k4 = k3 ^ (k3>>33)


C = 0xc4ceb9fe1a85ec53 * 0xff51afd7ed558ccd
x = k4
assert 0 == (x ^ (x*C) ^ (x>>33)) % 2**64
```

<br>

Now split into MSB and LSB

```python
k = 13621417624426829092
k2 = k ^ (k>>33)
k3 = k2 * 0xff51afd7ed558ccd % 2**64
k4 = k3 ^ (k3>>33)
y = k4 >> 33 
z = k4 % 2**33


C = 0xc4ceb9fe1a85ec53 * 0xff51afd7ed558ccd
assert 0 == ((y*2**33+z) ^ ((y*2**33+z)*C) ^ y) % 2**64
assert (C*y*2**33+z*C) % 2**64 == (y*2**33+z) ^ y
```

<br>

Then apply this identity: `a ^ b = a + b - 2 * (a & b)`

```python
assert (C*y*2**33+z*C) % 2**64 == (y*2**33+z+y) - 2 * ((y*2**33+z) & y)
```

<br>

in `(y*2**33+z) & y` the msb gets discarded

```python
assert (C*y*2**33+z*C) % 2**64 == (y*2**33+z+y) - 2*(y&z)
```

<br>

Factor out constants:

```python
A = 2**33*(1-C) + 1
B = 1-C
assert (A*y + B*z) % 2**64 == 2*(y&z)
```

<br>

This will be our main equation, we can't really simplify it any further. 

<br>


---




<br>

<br>

<br>

<br>

<br>

<br>

<br>

<br>

<br>

<br>

<br>

<br>

<br>

<br>

<br>

<br>

<br>

<br>

<br>

<br>

---

<br>

<br>

<br>



Author's solver:

```cpp
/* g++ -O3 -o brute brute.cpp -lgmp */
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <fplll/fplll.h>

using namespace fplll;

#define UINT128(hi, lo) (((__uint128_t) (hi)) << 64 | (lo))
#define F(y, z) ((A_lo * (y) + B_lo * (z)) ^ 2 * ((y) & (z)))

#define PREC 128
#define NTHREADS 8

/* mix constants */
const __uint128_t C = UINT128(0x9f3887bfd91f1f50, 0xed77e7f1c90aa277);
const int S = 65;

const __uint128_t A = (1 - ((__uint128_t)1 << S) * (C - 1));
const __uint128_t B = 1 - C;
const int K = 33;
const int N = 128;

const uint64_t A_hi = A >> 64, A_lo = A & 0xffffffffffffffff;
const uint64_t B_hi = B >> 64, B_lo = B & 0xffffffffffffffff;

static void print_u128(__uint128_t x) {
  printf("0x%016lx%016lx", (uint64_t)(x >> 64), (uint64_t)(x & 0xffffffffffffffff));
}

struct thread_ctx {
  mpfr_t g[3][3], l[3][3];
  mpfr_t d0, d1, d2, t0, t1, t2, tmp;
};

static void solve_lattice(uint64_t y_lo, uint64_t z_lo, thread_ctx *ctx) {
  const __uint128_t D = (2 * (y_lo & z_lo) - A * y_lo - B * z_lo) >> K;
  const __uint128_t D4 = D * 4;
  const uint64_t D4_hi = D4 >> 64, D4_lo = D4 & 0xffffffffffffffff;

  mpfr_set_ui(ctx->d0, D4_hi, MPFR_RNDN);
  mpfr_mul_2ui(ctx->d0, ctx->d0, 64, MPFR_RNDN);
  mpfr_add_ui(ctx->d0, ctx->d0, D4_lo, MPFR_RNDN);
  mpfr_add(ctx->d0, ctx->d0, ctx->t0, MPFR_RNDN);
  mpfr_set(ctx->d1, ctx->t1, MPFR_RNDN);
  mpfr_set(ctx->d2, ctx->t2, MPFR_RNDN);

  // iteration 1
  mpfr_fmma(ctx->tmp, ctx->d0, ctx->g[2][0], ctx->d1, ctx->g[2][1], MPFR_RNDN);
  mpfr_fma(ctx->tmp, ctx->d2, ctx->g[2][2], ctx->tmp, MPFR_RNDN);
  mpfr_round(ctx->tmp, ctx->tmp);
  mpfr_fma(ctx->d0, ctx->l[2][0], ctx->tmp, ctx->d0, MPFR_RNDN);
  mpfr_fma(ctx->d1, ctx->l[2][1], ctx->tmp, ctx->d1, MPFR_RNDN);
  mpfr_fma(ctx->d2, ctx->l[2][2], ctx->tmp, ctx->d2, MPFR_RNDN);

  // iteration 2
  mpfr_fmma(ctx->tmp, ctx->d0, ctx->g[1][0], ctx->d1, ctx->g[1][1], MPFR_RNDN);
  mpfr_fma(ctx->tmp, ctx->d2, ctx->g[1][2], ctx->tmp, MPFR_RNDN);
  mpfr_round(ctx->tmp, ctx->tmp);
  mpfr_fma(ctx->d0, ctx->l[1][0], ctx->tmp, ctx->d0, MPFR_RNDN);
  mpfr_fma(ctx->d1, ctx->l[1][1], ctx->tmp, ctx->d1, MPFR_RNDN);
  mpfr_fma(ctx->d2, ctx->l[1][2], ctx->tmp, ctx->d2, MPFR_RNDN);

  // iteration 3
  mpfr_fmma(ctx->tmp, ctx->d0, ctx->g[0][0], ctx->d1, ctx->g[0][1], MPFR_RNDN);
  mpfr_fma(ctx->tmp, ctx->d2, ctx->g[0][2], ctx->tmp, MPFR_RNDN);
  mpfr_round(ctx->tmp, ctx->tmp);
  mpfr_fma(ctx->d0, ctx->l[0][0], ctx->tmp, ctx->d0, MPFR_RNDN);
  mpfr_fma(ctx->d1, ctx->l[0][1], ctx->tmp, ctx->d1, MPFR_RNDN);
  mpfr_fma(ctx->d2, ctx->l[0][2], ctx->tmp, ctx->d2, MPFR_RNDN);

  // final
  mpfr_sub(ctx->d1, ctx->t1, ctx->d1, MPFR_RNDN);
  mpfr_sub(ctx->d2, ctx->t2, ctx->d2, MPFR_RNDN);

  __uint128_t y_hi = mpfr_get_si(ctx->d1, MPFR_RNDN);
  __uint128_t z_hi = mpfr_get_si(ctx->d2, MPFR_RNDN) >> 2;
  y_hi &= (((__uint128_t)1 << (N - S - K)) - 1);
  z_hi &= (((__uint128_t)1 << (S - K)) - 1);
  __uint128_t y = y_hi << K | y_lo;
  __uint128_t z = z_hi << K | z_lo;
  __uint128_t x = y << S | z;

  for (__uint128_t e = 0; e < 8; e++) {
    // sometimes there is error in the high bits for whatever reason...
    __uint128_t xx = x ^ (e << (N - S - K - 3));
    if ((xx ^ xx >> S ^ xx * C) == 0) {
      // the actual solution will be y ^ y >> 65 where y = x * 0xc4ceb9fe1a85ec53c4ceb9fe1a85ec53
      printf("found: ");
      print_u128(x);
      puts("");
    }
  }
}

static void hensel_lift(uint64_t y, uint64_t z, int i, thread_ctx *ctx) {
  /* Generate all z s.t. A*y + B*z = y & z (mod 2^k) */
  if (i == K) {
    solve_lattice(y, z, ctx);
    return;
  }
  uint64_t m = 1ULL << i, mask = (m << 1) - 1;
  if ((F(y, z) & mask) == 0) {
    hensel_lift(y, z, i + 1, ctx);
  }
  if ((F(y, z | m) & mask) == 0) {
    hensel_lift(y, z | m, i + 1, ctx);
  }
}

static void precompute_lattice(thread_ctx *ctx) {
  FP_NR<mpfr_t>::set_prec(PREC);

  mpz_t mod_mpz, A_mpz, B_mpz;
  mpz_inits(mod_mpz, A_mpz, B_mpz, (mpfr_ptr)0);
  mpz_ui_pow_ui(mod_mpz, 2, N - K);
  mpz_set_ui(A_mpz, A_hi);
  mpz_mul_2exp(A_mpz, A_mpz, 64);
  mpz_add_ui(A_mpz, A_mpz, A_lo);
  mpz_set_ui(B_mpz, B_hi);
  mpz_mul_2exp(B_mpz, B_mpz, 64);
  mpz_add_ui(B_mpz, B_mpz, B_lo);

  // scaling factor (*= 4)
  mpz_mul_2exp(A_mpz, A_mpz, 2);
  mpz_mul_2exp(B_mpz, B_mpz, 2);
  mpz_mul_2exp(mod_mpz, mod_mpz, 2);

  size_t n = 3;
  ZZ_mat<mpz_t> M(n, n);

  M[0][0] = A_mpz;
  M[0][1] = 1;
  M[1][0] = B_mpz;
  M[1][2] = 4;
  M[2][0] = mod_mpz;

  lll_reduction(M);

  ZZ_mat<mpz_t> dummy;
  MatGSO<Z_NR<mpz_t>, FP_NR<mpfr_t>> gso(M, dummy, dummy, GSO_INT_GRAM);
  gso.update_gso();

  // compute gram-schmidt orthogonalized basis in G
  FP_mat<mpfr_t> G(n, n);
  FP_NR<mpfr_t> mu;
  for (int i = 0; i < n; ++i) {
    for (int j = 0; j < n; ++j) {
      G[i][j].set_z(M[i][j]);
    }
    for (int j = 0; j < i; ++j) {
      gso.get_mu(mu, i, j);
      for (int k = 0; k < n; ++k) {
          G[i][k] -= mu * G[j][k];
      }
    }
  }

  // mass mpfr initialization
  for (int i = 0; i < n; i++) {
    for (int j = 0; j < n; j++) {
      mpfr_init2(ctx->l[i][j], PREC);
      mpfr_set_z(ctx->l[i][j], M[i][j].get_data(), MPFR_RNDN);
      mpfr_neg(ctx->l[i][j], ctx->l[i][j], MPFR_RNDN);
    }
  }
  FP_NR<mpfr_t> z;
  for (int i = 0; i < n; i++) {
    G[i].dot_product(z, G[i]);
    for (int j = 0; j < 3; j++) {
      mpfr_init2(ctx->g[i][j], PREC);
      mpfr_div(ctx->g[i][j], G[i][j].get_data(), z.get_data(), MPFR_RNDN);
    }
  }
  mpfr_inits2(PREC, ctx->t0, ctx->t1, ctx->t2, ctx->tmp, (mpfr_ptr)0);
  mpfr_ui_pow_ui(ctx->t0, 2, N - S - K, MPFR_RNDN);      // t0 = 2**(N-S-K) + D
  mpfr_ui_pow_ui(ctx->t1, 2, N - S - K - 2, MPFR_RNDN);  // t1 = 2**(N-S-K-2)
  mpfr_ui_pow_ui(ctx->t2, 2, S - K, MPFR_RNDN);          // t2 = 2**(S-K)
  mpfr_inits2(PREC, ctx->d0, ctx->d1, ctx->d2, (mpfr_ptr)0);
}

static void *search(void *arg) {
  thread_ctx ctx;
  precompute_lattice(&ctx);

  uint64_t n = (uint64_t)arg;
  uint64_t start = n * ((1ULL << K) / NTHREADS);
  uint64_t end = n != NTHREADS - 1 ? (n + 1) * ((1ULL << K) / NTHREADS) : 1ULL << K;

  printf("starting thread %ld [%lu, %lu)\n", n, start, end);

  /* x >> S == x * M ^ x (mod 2^n) */
  for (uint64_t y = start; y < end; y++) {
    if ((y & 0xffffff) == 0) {
      printf("checkpoint: %lx\n", y);
    }
    hensel_lift(y, 0, 0, &ctx);
  }
  return NULL;
}

int main() {
  pthread_t threads[NTHREADS];
  for (size_t i = 0; i < NTHREADS; i++) {
    pthread_create(&threads[i], NULL, search, (void *)i);
  }
  for (size_t i = 0; i < NTHREADS; i++) {
    pthread_join(threads[i], NULL);
  }
  return 0;
}
```

<br>


```
solution is x = 0x77140a2f515f7d36838035cbd1a4412c; reduce the problem to A*x_hi + B*x_lo = 2*(x_hi&x_lo) → solve with hensel lifting + fast lattice enumeration (brute force takes ~1hr on a decent cpu) https://cybersharing.net/s/13bb2797db22f55736160614dbc17042
```



```
ictf{d1d_y0u_u53_l4tt1c3_3num3r4t10n_0r_s0m3th1ng_else?}
```

<br>

```python
def f(k):
    k ^= k >> 65
    k *= 0xff51afd7ed558ccdff51afd7ed558ccd
    k &= 0xffffffffffffffffffffffffffffffff
    k ^= k >> 65
    k *= 0xc4ceb9fe1a85ec53c4ceb9fe1a85ec53
    k &= 0xffffffffffffffffffffffffffffffff
    k ^= k >> 65
    return k

k = 158282184008579085165054268258795143468 
assert f(k) == k


y = 5369030637032295174
z = 2048148011573908109
C = 0xff51afd7ed558ccdff51afd7ed558ccd * 0xc4ceb9fe1a85ec53c4ceb9fe1a85ec53
A = 2**65*(1-C) + 1
B = 1-C

assert (A*y + B*z) % 2**128 == 2*(y&z)
```
