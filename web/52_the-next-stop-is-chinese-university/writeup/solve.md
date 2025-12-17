# The Next stop is Chinese University

> - Author: sup
> - Difficulty: 2/5
>
> Flag: cuhk25ctf{C1t1c4l_cV3_hUH_3z_0n3_11ne_m1DD13w4R3_b7p45s_l0l}

Hmm, this is a Next.js website **using a middleware** for authentication. Remember that earlier in the year, there was quite a big news about a vulnerability of **Next.js's middleware**. For more details, check out the official blog [here](https://vercel.com/blog/postmortem-on-next-js-middleware-bypass).

This CVE is about bypassing the middleware of Next.js, which means we may be able to use this exploit to skip the middleware and directly get content in `/secret`. Refer to [this article](https://zhero-web-sec.github.io/research-and-things/nextjs-and-the-corrupt-middleware) for more information on the reason behind.

TL;DR: since we can see that the middleware is inside the `src` folder, we can add the following header when requesting `/secret` to bypass the middleware:

```
x-middleware-subrequest: src/middleware:src/middleware:src/middleware:src/middleware:src/middleware
```

Username and password does not matter here as, well, the whole authentication of the website is skipped thanks to this header.
