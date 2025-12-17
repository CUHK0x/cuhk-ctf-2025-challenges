# 🍪 I Want More Cookies

> - **Author:** F Chui  
> - **Difficulty:** 1/5  
> - **Flag:** `cuhk25ctf{1_LuV_Co0k135_X_minT_choc0l@te}`

---

##  Challenge Overview

This challenge is an ode to sweet treats and browser quirks. Players navigate multiple cookie stages, encoding values in Base64 and crafting a valid token, then forging a proper HMAC to pass the final check. 

---

##  Stage 1–3: Cookie Encoding

The first 3 stages ask to set specific cookies, each containing a Base64-encoded keyword.

| Stage | Keyword    | Cookie Value            | Cookie Name |
|-------|------------|-------------------------|-------------|
| 1     | `chocolate`| `Y2hvb2NvbGF0ZQ==`      | `cookie1`   |
| 2     | `chip`     | `Y2hpcA==`              | `cookie2`   |
| 3     | `yummy`    | `eXVtbXk=`              | `cookie3`   |

Hints were tucked into the HTML console and styled clues on the page.

---

##  Stage 4: Token Hashing

Once the cookies are correctly set, it’s token time. Base64 encoded SECRET is stored in the value of `"token"` cookie.

`"token"` = `Y29va2llX21vbnN0ZXJfMTMzNw==`

Decode it with Base64 will get `"cookie_monster_1337"`

Set the value of `"token"` cookie to `"chocolatechipyummycookie_monster_1337"` to move to the final stage.

## Stage 5: Signature Forgery (HMAC)

Players are asked to set a `"user"` cookie and a `"signature"` cookie, and match the value of `"signature"` with the HMAC encryted value of `"user"`

For example:

`"user"` = admin
`"signature"` = HMAC-SHA256(secret, user)   where secret (aka the key) is hidden in the `"final.html"`

Set the correct value of `"signature"` and get the flag!!!