# What is in the pic

**Challenge Info**

**Author:** F Chui
**Difficulty:** 0/5
**Category:** Forensics
**Flag:** cuhk25ctf{u_G0t_1t_Isnt_1t_39sY_3NJ0y_1c3_Cre9Ms}

---

## Challenge Overview

This challenge involves using image tools like exiftool and steghide. Get the password from metadata and unlock `"flag.txt"` embedded in `"suspicious.jpg"`with the password.

---

Try `"exiftool"` to see if anything weird in the metatdata. Then you can see some hints in the Software, User Comment and User Description.

Get the number of chicken (aka 5) and then get the password: `"iceCream05"`

Then, use `"steghide"` command to extract the embedded file which is locked with the password.

Viola, you got the flag! :)