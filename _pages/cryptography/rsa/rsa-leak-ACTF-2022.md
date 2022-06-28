---
permalink: /cryptography/rsa/rsa-leak-ACTF-2022
title: rsa_leak ACTF 2022
---

<br>

## Challenge

```python
def leak(a, b):
    p = random_prime(pow(2, 64))
    q = random_prime(pow(2, 64))
    n = p*q
    e = 65537
    print(n)
    print((pow(a, e) + pow(b, e) + 0xdeadbeef) % n)


def gen_key():
    a = randrange(0, pow(2,256))
    b = randrange(0, pow(2,256))
    p = pow(a, 4)
    q = pow(b, 4)
    rp = randrange(0, pow(2,24))
    rq = randrange(0, pow(2,24))
    pp = next_prime(p+rp)
    qq = next_prime(q+rq)
    if pp % pow(2, 4) == (pp-p) % pow(2, 4) and qq % pow(2, 4) == (qq-q) % pow(2, 4):
        n = pp*qq
        rp = pp-p
        rq = qq-q
        return n, rp, rq
    
n, rp, rq = gen_key()
e = 65537
c = pow(bytes_to_long(flag), e, n)
print("n =", n)
print("e =", e)
print("c =", c)
print("=======leak=======")
leak(rp, rq)

'''
n = 3183573836769699313763043722513486503160533089470716348487649113450828830224151824106050562868640291712433283679799855890306945562430572137128269318944453041825476154913676849658599642113896525291798525533722805116041675462675732995881671359593602584751304602244415149859346875340361740775463623467503186824385780851920136368593725535779854726168687179051303851797111239451264183276544616736820298054063232641359775128753071340474714720534858295660426278356630743758247422916519687362426114443660989774519751234591819547129288719863041972824405872212208118093577184659446552017086531002340663509215501866212294702743
e = 65537
c = 48433948078708266558408900822131846839473472350405274958254566291017137879542806238459456400958349315245447486509633749276746053786868315163583443030289607980449076267295483248068122553237802668045588106193692102901936355277693449867608379899254200590252441986645643511838233803828204450622023993363140246583650322952060860867801081687288233255776380790653361695125971596448862744165007007840033270102756536056501059098523990991260352123691349393725158028931174218091973919457078350257978338294099849690514328273829474324145569140386584429042884336459789499705672633475010234403132893629856284982320249119974872840
=======leak=======
122146249659110799196678177080657779971
90846368443479079691227824315092288065
'''
```

<br>

## Solve 

First solving for rp and rq, which are both less than $$2^{24}$$: <br>
We can loop over rp and solve for rq each time, breaking if we find one where rq < $$2^{24}$$.

leak_n = 122146249659110799196678177080657779971 <br>
leak_value = 90846368443479079691227824315092288065 <br>

leak_value $$\equiv {(rp)}^e + {(rq)}^e +$$ 0xdeadbeef (mod leak_n) <br>
leak_value $$- {(rp)}^e -$$ 0xdeadbeef $$\equiv {(rq)}^e$$  (mod leak_n) <br>
( leak_value $$- {(rp)}^e -$$ 0xdeadbeef $$)^{e^{-1}} \equiv rq$$  (mod leak_n) <br>

```python
from tqdm import tqdm

leak_value = 90846368443479079691227824315092288065
leak_n = 122146249659110799196678177080657779971
leak_p, leak_q = 8949458376079230661, 13648451618657980711
e = 65537

for rp in tqdm(range(2**26)):
    rq = pow((leak_value - pow(rp,e,leak_n) - 0xdeadbeef), pow(e, -1, (leak_p-1)*(leak_q-1)), leak_n) % leak_n
    if rq < 2**24:
        break

print(rp, rq)
```

<br>

We get rp = 405771 and rq = 11974933.

We're given $$pp = a^4 + rp, \ qq = b^4 + rq$$ and $$n = pp \cdot qq$$  

n $$= (a^4 + rp)(b^4 + rq)$$ <br>
$$ \ \ = (ab)^4 + rq \cdot a^4 + rp \cdot b^4 + rp \cdot rq$$

Now the term $$(ab)^4$$ is significantly larger than all others, so in fact we can do $$ab = \sqrt[4]{n}$

```python
ab = iroot(n,4)[0]
```

<br>

Now let's work in terms of p and q instead of a and b:

pq = $$(ab)^4$$ <br>

$$\ n = pq + rq \cdot p + rp \cdot q + rp \cdot rq$$
$$\ rq \cdot p + rp \cdot q = n - pq - rp \cdot rq$$
