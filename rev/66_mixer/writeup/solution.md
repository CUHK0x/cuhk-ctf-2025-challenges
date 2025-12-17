# Mixer
## TL;DR
The flag is embedded inside a certain string that is shuffled and given to the user. The rng used for the shuffling is seeded by the current time in seconds (only the integral part), meaning the shuffling is actually predictable. The flag can be recovered by doing the process in reverse.

## Challenge Overview
The binary is written in Rust. The hard part will not be figuring out what it is doing, but figure out the implementation details and implementing the reverse program.
RNG used: `SmallRng`
RNG seed: Time since epoch in u64
Shuffling: Fisher-Yates, starting from the front

## Solution
Implement a program using the solving algorithm below.

## Solving Algorithm
1. Seed the RNG by using the local system time and push them onto a stack.
2. From last element to the front element, pop a value from the stack, compute the shuffling index and swap it with the current one, since swapping again inverts the swapping made originally.
3. Get the unshuffled string

Note that there might be time difference. Perform the procedure multiple times until you find the flag.
