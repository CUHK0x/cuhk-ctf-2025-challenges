use rand::prelude::*;
use regex::{self, Regex};
use std::io::prelude::*;
use std::net::TcpStream;
use std::time;
use std::{env, io};

fn process(s: &[u8], seed: u64) -> String {
    let mut rng = SmallRng::seed_from_u64(seed);
    let target_line = s;
    let mut target_line: Vec<u8> = target_line.iter().cloned().collect();
    // Generate the sequences of rng so that we can do it in reverse
    let out_stk: Vec<u64> = (0..target_line.len()).map(|_| rng.next_u64()).collect();
    for (i, rng_out) in (0..target_line.len()).rev().zip(out_stk.iter().rev()) {
        let swap_idx = (rng_out % (target_line.len() - i) as u64) + i as u64;
        target_line.swap(i, swap_idx as usize);
    }
    String::from_utf8(target_line).expect("Should be ASCII (i.e. UTF-8)")
}

fn main() {
    let target: String = if env::args().len() > 1 {
        let remote_addr = env::args()
            .nth(1)
            .expect("Please provide an address as argument!");
        let mut stream =
            TcpStream::connect(remote_addr).expect("Should be able to open TCP stream to remote.");
        let mut out = String::new();
        stream
            .read_to_string(&mut out)
            .expect("Something to be read from remote, and should be UTF-8.");
        out.lines().nth(1).unwrap().to_string()
    } else {
        print!("Enter output from remote: ");
        io::stdout()
            .flush()
            .expect("Should be able to flush stdout");
        let mut buf = String::new();
        io::stdin()
            .lock()
            .read_line(&mut buf)
            .expect("Should be able to read a line from stdin");
        buf
    };
    let current_secs = time::SystemTime::now()
        .duration_since(time::UNIX_EPOCH)
        .expect("Should be able to unpack time")
        .as_secs();
    const MAX_TRIAL: u64 = 100;
    for dt in 0..MAX_TRIAL {
        let seed = current_secs - dt;
        let ans = process(target.trim().as_bytes(), seed);
        let flag_pattern = Regex::new("cuhk25ctf\\{.*\\}").unwrap();
        let search_result = flag_pattern.find(ans.as_str());
        if let Some(m) = search_result {
            println!("{}", m.as_str());
            return;
        }
    }
    println!("Tried seed for {MAX_TRIAL}s before and flag is not found.");
}
