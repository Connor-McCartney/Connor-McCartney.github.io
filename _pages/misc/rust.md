

Rayon parallelism mini project:

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

```rs
use std::collections::HashSet;
use rug::Integer;
use rayon::prelude::*;
use std::sync::{Arc, Mutex};
use linya::{Bar, Progress};

fn modular_nth_root(x: Integer, n: Integer, e: Integer, rounds: u64) -> Vec<Integer>{
    let one = Integer::from(1); 
    let phi_coprime = (n.clone()-one.clone()) / e.clone();
    let progress = Mutex::new(Progress::new());
    let roots = Arc::new(Mutex::new(HashSet::new()));
    let bar1: Bar = progress.lock().unwrap().bar(rounds as usize, "...");
    let bar2: Bar = progress.lock().unwrap().bar(100, "...");
    let m = Mutex::new(0);

    (1_u64..rounds).into_par_iter().try_for_each(|i| Some({
        let mut count = m.lock().unwrap();
        *count += 1;


        let l = roots.lock().unwrap().len();
        if l == e {
            return None;
        }
        progress.lock().unwrap().set_and_draw(&bar1, *count);
        progress.lock().unwrap().set_and_draw(&bar2, (l*100)/(e.to_i64().unwrap() as usize));

        let u = match (Integer::from(i)).pow_mod(&phi_coprime, &n) {
            Ok(u) => u,
            Err(_) => unreachable!(),
        };
        roots.lock().unwrap().insert(u);
    }));

    let d = match e.pow_mod(&Integer::from(-1), &phi_coprime) {
        Ok(d) => d,
        Err(_) => unreachable!(),
    };

    let v = match x.pow_mod(&d, &n) {
        Ok(v) => v,
        Err(_) => unreachable!(),
    };
    let mut ret: Vec<Integer> = vec![];
    roots.lock().unwrap().iter().for_each(|i| {
        let t = (v.clone() * i).modulo(&n);
        ret.push(t);
    });
    return ret
}

fn main() {
    let e = Integer::from(56941);
    let p_str = "99008709926315299091317669357309331804845329790751953851753268738503540104659";
    let c_str = "31913011624546690195521115703293649002421770313268738797652443889880621517880";
    let p = p_str.parse::<Integer>().unwrap();
    let c = c_str.parse::<Integer>().unwrap();

    let rounds: u64 = 1_000_000;
    let roots = modular_nth_root(c, p, e, rounds);
    for i in roots.iter() {
        println!("{:?}", i);
    }   

}
```
