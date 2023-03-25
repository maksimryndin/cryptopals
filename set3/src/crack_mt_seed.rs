/// https://cryptopals.com/sets/3/challenges/22
use std::time::SystemTime;

pub fn unix_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mersenne_twister::MersenneTwister;
    use set2::ecb_cbc_oracle::rand_range;
    use std::sync::mpsc::channel;
    use std::thread;

    #[test]
    fn mersenne_seed_crack() {
        let now = unix_timestamp() as u32;
        let slept = now + rand_range(2, 10) as u32 * 25_u32; // simulating sleep
                                                             // let d = Duration::from_secs(rand_range(2, 10) as u64 * 25_u64);
                                                             // sleep(d);
        let seed = slept;
        let mut rng = MersenneTwister::new(seed);
        let slept = slept + rand_range(2, 40) as u32 * 25_u32;
        // let d = Duration::from_secs(rand_range(2, 40) as u64 * 25_u64);
        // sleep(d);
        let output = rng.next().unwrap();

        println!("bruteforcing output {output}");
        let now = slept; //unix_timestamp() as u32;

        let (tx, rx) = channel();
        let num_threads = thread::available_parallelism().unwrap().get() as u32;
        println!("using {num_threads} threads");
        let step = 1000 / num_threads;

        (0..num_threads).for_each(|i| {
            let tx = tx.clone();
            let start = now - step * i as u32;
            let end = now - step * (1 + i as u32) + 1;
            let builder = thread::Builder::new().name(format!("thread-{i}"));
            builder
                .spawn(move || {
                    println!("starting thread {i} with starting seed {start}");
                    let mut s = start;
                    let mut rng = MersenneTwister::new(s);
                    while output != rng.next().unwrap() {
                        s -= 1;
                        if s < end {
                            println!("exiting thread {i} w/o result");
                            return;
                        }
                        rng = MersenneTwister::new(s)
                    }
                    tx.send(s).unwrap();
                    println!("exiting thread {i} with seed {s}");
                })
                .expect("failed to start thread {i} with starting seed {start}");
        });

        let s = rx.recv().unwrap();
        assert_eq!(s, seed);
    }
}
