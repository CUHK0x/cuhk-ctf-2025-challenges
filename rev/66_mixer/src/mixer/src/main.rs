use std::{env, time, vec};

use rand::prelude::*;

fn proc(s: &[u8], rng: &mut SmallRng) -> Vec<u8> {
    let mut a = vec![0u8; s.len()];
    a.copy_from_slice(s);
    for i in 0..a.len() {
        let x = rng.next_u64();
        let swap_idx = (x % (s.len() - i) as u64) + i as u64;
        a.swap(i, swap_idx as usize);
    }
    a
}

fn main() {
    let seed = time::SystemTime::now().duration_since(time::UNIX_EPOCH).expect("Should be able to unpack time").as_secs();
    let mut rng = SmallRng::seed_from_u64(seed);
    let Some(flag) = env::var_os("FLAG") else {
        panic!("You will need an input :) If you see this in the remote machine, contact challenge author.")
    };
    let flag = flag.as_encoded_bytes();
    // append extra garbage
    let prefix = "youhimherherhim".as_bytes();
    let postfix = "herherhimhimstrangernobody".as_bytes();
    let f = [&prefix[..], &flag[..], &postfix[..]].concat();
    let Ok(output) = String::from_utf8(proc(f.as_slice(), &mut rng)) else {
        panic!("String is not UTF-8!");
    };
    println!("Stuff:");
    println!("{output}");
}
