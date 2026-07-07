# From Detection to Disclosure: Analysis and Documentation of an XSS in Microsoft

> **Author**: Rahul Hoysala
> **Published**: Dec 12, 2025

---

![Rahul Hoysala](https://miro.medium.com/v2/resize:fill:32:32/1*oWzoi9vID30bAzAJofB2Xg.jpeg)

--

--

Listen

Share

Researchers, analysts, bug hunters, lend me your ears — I come to bury cyber threats, not inflict them…

The following is a public disclosure of a vulnerability I discovered in Microsoft’s infrastructure. This aims to aid security researchers and beginners to the field in honing methodologies and understanding how to successfully leverage them to prove real-world impact.

![image](https://miro.medium.com/v2/resize:fit:700/0*b0WwVEeFs7dRzcDU)

## 👑 Reconnaissance: The King of Security

It all began from a simple Google search. 👀

In the realm of passive reconnaissance, Google dorking is of massive importance. For those unfamiliar with this term, it refers to using specialized search queries and parameters/operators to find content which would have otherwise not been easily viewable in the indexed results. (✨Pro tip: Check out LegionHunter’s blogs on Medium for amazing content on advanced Google dorking!)

## 🤔 But what exactly did I expect to uncover?

Having recently found a plethora of old CVEs in other organizations recently — I deemed it highly likely that companies might still be using certain legacy vulnerable components that might lead to the uncovering of this vulnerability. With this in mind, I used the particular Google dork I was targeting the vulnerability with (which is, as of now, undisclosed as part of the CVD engagement) — and immediately struck gold.

## 🔍 Looking at it closely: Did I strike gold or pyrite?

After carefully analyzing the discovery multiple times to draw an exact map of the attack path, here was how it went. I found a multi-layered mine of CWE-601 — otherwise known as an open redirect vulnerability. BUT, this wasn’t just any open redirect, where you modify a parameter to redirect to arbitrary sites — this was much more unusual and unique in the attack chain.

## 🔪 Dissecting the vulnerability

For this section, let’s assume our primary domain to be microsoft.com, which is the domain that we’re testing.

And let’s say there was a product page which Microsoft issues redirects to on it’s website. These would not just include the home pages themselves, or the primary product domains themselves (such as xbox.com or windows.com), but would also include domains which are owned and managed by Microsoft as part of their product services. In my case, the intermediary domain was azurewebsites.net, which Microsoft’s primary domain was issuing a redirect to. This makes sense because Microsoft might have readily whitelisted a domain which they control.

In the case of azurewebsites.net, it’s a domain operated by Microsoft. It’s a domain used within the Azure platform for hosting and managing web applications. So anyone hosting a site on Azure Web Apps in the format of <YOURSITE>.azurewebsites.net would have it always resolve to the Azure App Service.

## Get Rahul Hoysala’s stories in your inbox

Join Medium for free to get updates from this writer.

Remember me for faster sign in

And that was where the vulnerability lay — this was, in particular, affected by something similar to CVE-1999–0869 - leading to reflected XSS. (Pre-Y2K CVE, that’s rare.)

The nature of this XSS was that it was reflected in the URL. So let’s say the URL was something.azurewebsites.net/some/path/here.ext. The XSS was triggered by the following URL: something.azurewebsites.net/some/path/here.ext#javascript:alert("XSS").

Upon testing it, an alert box was immediately popped, confirming the presence of reflected XSS!

But is that it? No, it can also be leveraged for a different kind of open redirect with the following URL: something.azurewebsites.net/some/path/here.ext#javascript:window.top.location.href='https://google.com';.

Essentially, we’re changing the location of the top window to an arbitrary site. So if you were changing a secondary window or an iframe in this context, the arbitrary site would load within the intermediary domain, assuming there was a frame that supported it. But in this case, since we’re changing the top window’s location, it essentially tells the browser to redirect to the parameter provided in the href attribute. Essentially, it redirects to an arbitrary site.

Let’s consider the following diagram:

![image](https://miro.medium.com/v2/resize:fit:700/1*2Fwp4aupaXk6mT1oAjyD0w.png)

So, in a phishing scenario: if someone sends you a link which has it’s primary domain as Microsoft, and you click on it immediately without thinking twice, you’re eventually redirected to an arbitrary site in around two seconds. This is done by leveraging the reflected XSS in the intermediary domain to manipulate the top window to redirect again to a completely different, malicious domain.

Just imagine: a threat actor targets an employee in a company via email. They send a Microsoft link to the employee. The catch is, the Microsoft link is totally legitimate — no URL masking or typosquatting. Then, when they click on it, it redirects to the Azure-hosted site, which triggers an XSS, which can be used to redirect to any arbitrary site for dropping malware on the system. What’s more impactful is that tightly-controlled corporate inboxes tend to have Microsoft domains whitelisted.

## 🔨 What was Microsoft’s verdict?

I reported this vulnerability to Microsoft, with POC links and screen recordings, and I received a response within a few days, had my report status change to review/reproduction. Within a few more days, my report was classified as moderate severity.

## 📚 References

## What is reflected XSS (cross-site scripting)? Tutorial & Examples | Web Security Academy

### In this section, we'll explain reflected cross-site scripting, describe the impact of reflected XSS attacks, and spell…

portswigger.net

## Open redirection (reflected)

### Open redirection vulnerabilities arise when an application incorporates user-controllable data into the target of a…

portswigger.net

## Microsoft Security Response Center

### The Microsoft Security Response Center is part of the defender community and on the front line of security response…

msrc.microsoft.com

## Build software better, together

### GitHub is where people build software. More than 150 million people use GitHub to discover, fork, and contribute to…

github.com



---
*Original URL: [https://medium.com/@rahulhoysala07/from-detection-to-disclosure-analysis-and-documentation-of-an-xss-in-microsoft-d0d7dc196460?source=search_post---------118-----------------------------------](https://medium.com/@rahulhoysala07/from-detection-to-disclosure-analysis-and-documentation-of-an-xss-in-microsoft-d0d7dc196460?source=search_post---------118-----------------------------------)*
