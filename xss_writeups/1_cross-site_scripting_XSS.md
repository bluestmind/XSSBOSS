# 1. cross-site scripting (XSS)

> **Author**: Osaid Ahmed Soh
> **Published**: Apr 27, 2026

---

![Osaid Ahmed Soh](https://miro.medium.com/v2/da:true/resize:fill:32:32/0*iyHBvjotO-pbA44s)

Listen

Share

## Encode data on output

Encoding should be applied directly before user-controllable data is written to a page, because the context you’re writing into determines what kind of encoding you need to use. For example, values inside a JavaScript string require a different type of escaping to those in an HTML context.

In an HTML context, you should convert non-whitelisted values into HTML entities:

- < converts to: &lt;
- > converts to: &gt;

In a JavaScript string context, non-alphanumeric values should be Unicode-escaped:

- < converts to: \u003c
- > converts to: \u003e

Sometimes you’ll need to apply multiple layers of encoding, in the correct order. For example, to safely embed user input inside an event handler, you need to deal with both the JavaScript context and the HTML context. So you need to first Unicode-escape the input, and then HTML-encode it:

<a href="#" onclick="x='This string needs two layers of escaping'">test</a>

## Validate input on arrival

Encoding is probably the most important line of XSS defense, but it is not sufficient to prevent XSS vulnerabilities in every context. You should also validate input as strictly as possible at the point when it is first received from a user.

Examples of input validation include:

- If a user submits a URL that will be returned in responses, validating that it starts with a safe protocol such as HTTP and HTTPS. Otherwise someone might exploit your site with a harmful protocol like javascript or data.
- If a user supplies a value that it expected to be numeric, validating that the value actually contains an integer.
- Validating that input contains only an expected set of characters.

Input validation should ideally work by blocking invalid input. An alternative approach, of attempting to clean invalid input to make it valid, is more error prone and should be avoided wherever possible.

## Whitelisting vs blacklisting

Input validation should generally employ whitelists rather than blacklists. For example, instead of trying to make a list of all harmful protocols (javascript, data, etc.), simply make a list of safe protocols (HTTP, HTTPS) and disallow anything not on the list. This will ensure your defense doesn't break when new harmful protocols appear and make it less susceptible to attacks that seek to obfuscate invalid values to evade a blacklist.

## Allowing “safe” HTML

Allowing users to post HTML markup should be avoided wherever possible, but sometimes it’s a business requirement. For example, a blog site might allow comments to be posted containing some limited HTML markup.

The classic approach is to try to filter out potentially harmful tags and JavaScript. You can try to implement this using a whitelist of safe tags and attributes, but thanks to discrepancies in browser parsing engines and quirks like mutation XSS, this approach is extremely difficult to implement securely.

The least bad option is to use a JavaScript library that performs filtering and encoding in the user’s browser, such as DOMPurify. Other libraries allow users to provide content in markdown format and convert the markdown into HTML. Unfortunately, all these libraries have XSS vulnerabilities from time to time, so this is not a perfect solution. If you do use one you should monitor closely for security updates.

## 2. Cross-site request forgery (CSRF)

In this section we’ll outline three alternative defenses against CSRF and a fourth practice which can be used to provide defense in depth for either of the others.

- The first primary defense is to use CSRF tokens embedded in the page. This is the most common method if you’re issuing state-changing requests from form elements, as in our example above.
- The second is to use Fetch metadata HTTP headers to check whether or not the state-changing request is being issued cross-site.
- The third is to ensure that state-changing requests are not simple requests, so that cross-origin requests are blocked by default. This method is appropriate if you’re issuing state-changing requests from JavaScript APIs like fetch().

Finally, we’ll discuss the SameSite cookie attribute, which can be used to provide defense in depth alongside either of the previous methods.

## CSRF tokens

In this defense, when the server serves a page, it embeds an unpredictable value in the page, called the CSRF token. Then when the legitimate page sends the state-changing request to the server, it includes the CSRF token in the HTTP request. The server can then check the token value and carries out the request only if it matches. Because an attacker can’t guess the token value, they can’t issue a successful forgery. Even if the attacker does discover a token after it has been used, the request can’t be replayed if the token changes every time.

## Get Osaid Ahmed Soh’s stories in your inbox

Join Medium for free to get updates from this writer.

Remember me for faster sign in

For form submissions, the CSRF token is usually included in a hidden form field, so that on form submission it is automatically sent back to the server for checking.

For a JavaScript API like fetch(), the token might be placed in a cookie or embedded in the page, and the JavaScript extracts the value and sends it as an extra header.

Modern web frameworks usually have built-in support for CSRF tokens: for example, Django enables you to protect forms using the csrf_token tag. This generates an additional hidden form field containing the token, which the framework then checks on the server.

To take advantage of this protection you must understand all the places in your website where you are using state-changing HTTP requests, and ensure you’re using the defense provided by your chosen framework.

## Fetch metadata

Fetch metadata is a collection of HTTP request headers, added by the browser, that provide extra information about the context of an HTTP request. The server can use these headers to decide whether to allow a request or not.

Most relevant for CSRF is the Sec-Fetch-Site header, which tells the server whether this request is same-origin, same-site, cross-site, or initiated directly by the user. The server can use this information to allow cross-origin requests, or block them as potential CSRF attacks.

For example, this Express code allows only same-site and same-origin requests:

```
app.post("/transfer", (req, res) => {
  const secFetchSite = req.headers["sec-fetch-site"];
  if (secFetchSite === "same-origin" || secFetchSite === "same-site") {
    console.log("allowed");
    // Update state
  } else {
    console.log("denied");
    // Don't update state
  }
});
```

See Fetch metadata request header for the complete list of Fetch metadata headers, and Fetch metadata for a guide to using this feature.

## Avoiding simple requests

Web browsers distinguish two sorts of HTTP requests: simple requests and other requests.

Simple requests, which are the sort of request that result from a <form> element submission, can be made cross-origin without being blocked. Since forms have been able to make cross-origin requests since the early days of the web, it's important for compatibility that they should still be able to make cross-origin requests. This is why we need to implement other strategies to defend forms against CSRF, such as using a CSRF token.

However, other parts of the web platform, in particular JavaScript APIs like fetch(), can make different sorts of requests (for example, requests that set custom headers), and these requests are by default not allowed cross-origin, so a CSRF attack would not succeed.

So a website that uses fetch() or XMLHttpRequest can defend against CSRF by ensuring that the state-changing requests that it issues are never simple requests.

For example, setting the request’s Content-Type to "application/json" will prevent it from being treated like a simple request:

```
fetch("https://my-bank.example.org/transfer", {
  method: "POST",
  headers: {
    "Content-Type": "application/json",
  },
  body: JSON.stringify({ recipient: "joe", amount: "100" }),
});
```

Similarly, setting a custom header on the request will prevent it being treated like a simple request:

```
fetch("https://my-bank.example.org/transfer", {
  method: "POST",
  headers: {
    "X-MY-BANK-ANTI-CSRF": 1,
  },
  body: JSON.stringify({ recipient: "joe", amount: "100" }),
});
```

The header name can be anything, as long as it doesn’t conflict with standard headers.

The server can then check for the existence of the header: if it exists, then the server knows that the request was not treated as a simple request.

### Non-simple requests and CORS

We’ve said that non-simple requests are by default not sent cross-origin. The catch is that the Cross-Origin Resource Sharing (CORS) protocol allows a website to relax this restriction.

Specifically, your website will be vulnerable to a CSRF attack from a particular origin if its response to a state-changing request includes:

- The Access-Control-Allow-Origin response header, and the header lists the sender's origin
- The Access-Control-Allow-Credentials response header.



---
*Original URL: [https://medium.com/@osaid.ahmed.soh/1-cross-site-scripting-xss-a197ed90b278?source=search_post---------26-----------------------------------](https://medium.com/@osaid.ahmed.soh/1-cross-site-scripting-xss-a197ed90b278?source=search_post---------26-----------------------------------)*
