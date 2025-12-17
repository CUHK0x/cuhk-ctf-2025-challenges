# TL;DR
The program requires the user to basically win the game, i.e. `spaceConsole.GoToSpace()` gracefully exits in the end. The user must enter correct input at right timings in order to win the game. Part of this function is multi-threaded, and input in different order may be read into the program, but ultimately rejects them when they are not in the correct order. The correct *conversation* (i.e. the sequence of both input and output) is written in [`final-ans.txt`](./final-ans.txt). **It is expected that there is only one possible set of inputs at the right timing that will lead to the final solution, and anything else is rejected.** That is, if `spaceConsole.GoToSpace()` returns a string, this string should be the correct conversation and exactly matches the contents in `final-ans.txt`.

# Constraints
- `CHECK system` should be used after `T=-120s`, and then `CHECK ground status`.
- `CHECK comms` should be used after `T=-60s`, then `CHECK ground launch auth`, and then `LAUNCH`.
- `COUNTDOWN` should be used after `T=-15s`, then 10 to 1, sequentially on separate lines.
- `DETACH booster stage 1` should be used between `100km` and `150km`.
- `DETACH booster stage 2` should be used between `300km` and `325km`.
- `SHUTDOWN thrusters` should be used between `325km` and `340km`.
- After `Approaching orbit altitude...` appears, enter the contents in [sync-part-input.txt](./sync-part-input.txt). There is no time constraint in this part.

# Final Answer
- SHA256 digest of the final input and output: `a51a979b4b2400351a2a535588a292cff48a2fa72b0a606abdef1bcbcaaf8e11`,  
  use this to decrypt the flag.
