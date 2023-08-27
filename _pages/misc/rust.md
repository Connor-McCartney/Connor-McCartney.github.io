

Rayon parallelism:

```rs
use std::collections::HashSet;
use num_bigint::BigUint;
use rayon::prelude::*;
use std::sync::{Arc, Mutex};

/*
num-bigint = "*"
zzz = "*"
rayon = "*"
*/

fn main() {
    let roots = Arc::new(Mutex::new(HashSet::new()));
    let m: BigUint = BigUint::parse_bytes(b"951831591126891226445616798859389634962506017435096204719527931037946751257386453", 10).unwrap(); 
    let phi_coprime: BigUint = BigUint::parse_bytes(b"9322268602557135700671055687486064414978071334192885661729116000880941316684", 10).unwrap(); 
    let limit: u64 = 1_000_000;

    (1_u64..limit).into_par_iter().for_each(|i| {
        let x: BigUint = (BigUint::from(i)).modpow(&phi_coprime, &m);
        roots.lock().unwrap().insert(x);
    });

    println!("roots = {:?}", roots.lock().unwrap());
}
```
