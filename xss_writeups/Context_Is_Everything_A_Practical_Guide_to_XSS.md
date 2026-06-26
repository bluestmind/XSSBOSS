# Context Is Everything: A Practical Guide to XSS

> **Author**: Marduk I Am
> **Published**: Mar 4, 2026

---

## Understanding XSS Using Five Portwigger Labs.

![Marduk I Am](https://miro.medium.com/v2/resize:fill:32:32/1*zFQ8mbLyUwfh4gnFly7u0w.png)

3

Listen

Share

![image](https://miro.medium.com/v2/resize:fit:700/1*J2CEnfN-V4U_sddNc7sKYg.jpeg)

A tour through the four execution contexts every web security researcher must understand.

## 🏠 Introduction

Cross-Site Scripting (XSS) is a vulnerability that allows an attacker to inject malicious code, usually JavaScript, into a web page viewed by another user. But how does our input, which starts as simple text, get transformed into executable code?

When a browser receives HTML from a server, it parses it and builds a tree of elements called the Document Object Model (DOM). Your input (whether from a search bar, form field, or comment box), gets reflected in that page and lands somewhere inside that tree at a specific location. Where it lands completely determines what you can do with it and what payload will work. This is the most important concept in XSS. Context is everything.

Think of the webpage as a house. Inside that house there are four different rooms into which your input can land. Each room has its own set of rules, its own furniture (syntax), and its own unique way to escape.

Your job when you land in a new room is to figure out three things:

- Where am I? — In which of the four contexts did my input land?
- What’s locked? — Which characters are filtered or encoded?
- What’s unlocked? — Which characters can I use to execute my escape plan?

This guide will walk you through each of the four main XSS contexts, using hands-on labs to demonstrate the thought process behind finding and exploiting these vulnerabilities.

## 🚪 Room 1: HTML body context

This is the most straightforward. Your input lands between tags as visible text.

```
<p>Welcome, Marduk!</p>
```

If the app does NOT sanitize, you can just inject raw HTML tags. <script>alert(1)</script> or <img src=x onerror=alert(1)> work here because the browser is in "parsing HTML" mode and will treat your angle brackets as real tags.

Go to the PortSwigger lab: “Reflected XSS into HTML context with nothing encoded”

Search for: M4rduk

Look in the page source:

```
<h1>0 search results for 'M4rduk'</h1>
```

Now test what happens with angle brackets. Search for: <i>M4rduk</i>

Look on the page. Your input is reflected but italicized. This lets you know the browser sees and interprets your <i> as real HTML.

Now look at the source:

```
<h1>0 search results for '<i>M4rduk</i>'</h1>
```

The angle brackets went through unchanged, but they’re inside an existing <h1> tag, which is messy. Try a tag that's designed to execute JavaScript. Like the classic ones mentioned earlier:

```
<script>alert(1)</script>

or

<img src=x onerror=alert(1)>
```

Both work. The reason is simple. Nothing was encoded or filtered. Your input became part of the HTML tree exactly as you sent it.

In the HTML body room, when angle brackets are untouched, you inject tags directly. No escape needed. Consider the door to the room was left opened. All you need to do is walk through.

## 🚪 Room 2: Attribute context

Your input lands inside an HTML attribute value.

```
<input value="Marduk" type="text">
<img alt="Marduk" src="photo.jpg">
```

You can’t just inject <script> here because you're inside a quoted attribute — the browser won't interpret a new tag until you break out of it.

Go to PortSwigger’s XSS labs and look at lab “Reflected XSS into attribute with angle brackets HTML-encoded”.

Search for: M4rduk

In the page source you can find ‘M4rduk’ inside the <input> attribute.

```
<input type="text" placeholder="Search the blog..." name="search" value="M4rduk">
```

Now notice what the lab name told you, “angle brackets HTML-encoded.” Test that. Search for <i>M4rduk</i> and look at the source. What does it look like?

```
<h1>0 search results for '<i>M4rduk</i>'</h1>
<input type="text" placeholder="Search the blog..." name="search" value="<i>M4rduk</i>">
```

But when you copy, from the DOM, and paste them in a text file, you can see the html encoding:

```
<input type="text" placeholder="Search the blog..." name="search" value="&lt;i&gt;M4rduk&lt;/i&gt;">
```

The app is HTML-encoding angle brackets: < becomes &lt; and > becomes &gt;. That means the HTML body context is a dead end. Even if your tags show up visually in the h1, they're encoded and the browser treats them as literal text, not markup. You can't inject a new tag.

But look at where you are in the attribute room. Your input is sitting inside value=”…”. The angle brackets are encoded but what character is not encoded?

The quote mark: "

Try this in the search box: " autofocus onfocus="alert(1)

An alert window should pop up. Click ok then look at the source:

```
<input type="text" placeholder="Search the blog..." name="search" value="" autofocus="" onfocus="alert(1)">
```

The first " closed the value attribute. Then you added two new attributes:

- autofocus — makes the browser automatically focus the element on page load.
- onfocus — fires JavaScript when that focus happens.

The closing " at the end was swallowed by the original closing quote that was already there.

So the browser saw a perfectly valid input tag with three attributes and executed your JavaScript automatically on page load. No user click required. And the key reason this worked while <script> wouldn't? You never needed angle brackets at all. You stayed inside the tag; you just added to it. The encoding that blocked HTML body injection was completely irrelevant here because you weren't trying to create new tags.

This is the mental shift. Before, you were thinking “can I inject JavaScript.” Now you should be thinking “what room am I in, what characters are and aren’t filtered, and what does that room let me do with those characters.”

One thing is worth burning into your memory from this. Whenever you see your input reflected in an attribute value, immediately check if quotes are encoded. That single question tells you whether attribute injection is possible.

In the attribute room, you break out of the attribute value with a quote and inject event handlers. No angle brackets needed.

## 🚪 Room 3: JavaScript context

Your input lands inside an existing script block.

```
<script>
  var username = "Marduk";
  var query = "Marduk";
</script>
```

Here, you’re already inside JavaScript, which gives you two possible escape routes:

- Break out of the script block entirely using </script> to return to HTML mode
- Break out of the string and stay within the script block using quotes and JavaScript syntax

Which one works? That depends entirely on what’s filtered. Let’s see what this lab allows.

Go to this lab: “Reflected XSS into a JavaScript string with single quote and backslash escaped”.

Search for: M4rduk

In the page source ‘M4rduk’ falls in 2 spots:

```
<section class=blog-header> <h1>0 search results for 'M4rduk'</h1> <hr> </section>
...
<script> 
    var searchTerms = 'M4rduk';
    document.write('<img src="/resources/images/tracker.gif?searchTerms='+encodeURIComponent(searchTerms)+'">');
</script>
```

Focus on the script block:

```
var searchTerms = 'M4rduk';
```

You’re inside a single-quoted JavaScript string. The lab says single quotes are escaped. Test that.

## Get Marduk I Am’s stories in your inbox

Join Medium for free to get updates from this writer.

Remember me for faster sign in

Search for M'4rduk and look at what happens to the quote in the source.

```
it got html encoded in the reflection:
<h1>0 search results for 'M&apos;4rduk'</h1>

and escaped in the script:
var searchTerms = 'M\'4rduk';
```

Single quotes are escaped with a backslash, which means you can’t break out of the string that way. And the lab title also told you backslashes are escaped too. Meaning if you tried \' the backslash itself would get escaped first, giving you \\\' which still traps you in the string.

So, breaking out of the string is blocked. But remember, you’re inside a <script> block. That means the browser is in JavaScript parsing mode. And there's one thing that can interrupt JavaScript parsing mode entirely and kick the browser back into HTML parsing mode.

Think about what that might be. What tag, if it appeared inside a script block, would make the browser stop parsing JavaScript? </script>

Try it. Search for: </script><img src=x onerror=alert(1)>

Then look at what the script block looks like in source.

```
<script> var searchTerms = '</script>
<img src=x onerror=alert(1)>';
```

Look at what happened. The browser was parsing JavaScript, hit </script>, and immediately switched back to HTML parsing mode. It didn't care that it was in the middle of a string. HTML parsing takes priority. Then it saw your <img> tag with the onerror handler and executed it.

The single quote escaping was completely irrelevant because you never tried to break out of the string. You broke out of the entire script block instead.

Find the lab: “Reflected XSS into a JavaScript string with angle brackets HTML encoded”

Same setup as before. Your input lands in a JavaScript string. But this time angle brackets are encoded, which means </script> won't work because the < and > will be neutralized.

So, you can’t break out of the script block. You’re stuck inside the JavaScript string. But go back to basics. The lab title says angle brackets are encoded. What does it not say is encoded or escaped? Think about what characters you’d need to break out of a single quoted JavaScript string itself, without using any angle brackets at all.

Search for M'4rduk again and find it in the script block in source.

```
<script>
    var searchTerms = 'M'4rduk';
    document.write('<img src="/resources/images/tracker.gif?searchTerms='+encodeURIComponent(searchTerms)+'">');
</script>
```

The single quote went through unescaped this time. You just found your escape route. You’re out of the string now. But you’re still inside a <script> block and you can't use angle brackets. You don't need them. You're already in JavaScript. You just need to write valid JavaScript from this point.

Think about what you need to do structurally. You opened the string with ', your input broke out of it with ', but now the rest of the original code, 4rduk'; and everything after, is sitting there and will cause a syntax error that might prevent your code from running.

How do you handle the code that comes after your injection point in JavaScript without using angle brackets? //

Search for ';alert(1);//

```
<script>
    var searchTerms = ''; alert(1);//';
    document.write('<img src="/resources/images/tracker.gif?searchTerms='+encodeURIComponent(searchTerms)+'">');
</script>
```

There it is. Clean execution.

The // commented out the '; that was left over, so the browser saw perfectly valid JavaScript with no syntax errors and executed your alert.

In the JavaScript string room, if you can’t break the string, you try to break out of the script block entirely with </script> and then you're back to HTML room rules.

Look at the full picture of what you just did across these two JS context labs:

- In the first one, single quotes were escaped but angle brackets weren’t, so you broke out of the script block entirely with </script>.
- In the second one, angle brackets were encoded but single quotes weren’t, so you broke out of the string with ' and wrote raw JavaScript, cleaning up with //.

The pattern is the same every time. Figure out what’s filtered, find what isn’t, use what’s available in that room to escape. You’re never looking for one magic payload. You’re reading the specific situation in front of you.

Ready for URL context? It’s a bit different from the others and has some interesting real world implications beyond just XSS.

## 🚪 Room 4: URL context

Okay, URL context. This one requires a slightly different mental model first. In the previous rooms you were breaking out of something, an HTML tag, a quoted string, a script block. URL context is really a special case of attribute context, but the browser gives URL attributes additional behavior (like supporting the javascript: protocol).

The classic setup looks like this:

```
<a href="https://example.com/search?q=M4rduk">click here</a>
```

But sometimes the app reflects your input as the entire href value, not just part of a URL:

```
<a href="M4rduk">click here</a>
```

When you control the whole href value, browsers support a special pseudo-protocol called javascript:. Meaning instead of https:// or http://, you can use javascript: and whatever follows gets executed as JavaScript when the link is clicked.

```
<a href="javascript:alert(1)">click here</a>
```

That’s the core of URL context XSS.

Now go find the lab: “Reflected XSS in canonical link tag”.

Open the lab and do your usual first step. Search for M4rduk using the URL itself. Append ?M4rduk to the end of https://YOUR-LAB-ID.web-security-academy.net/?M4rduk

Then look at the page source in the <head> section. What do you see?

```
<head>
    <link href=/resources/labheader/css/academyLabHeader.css rel=stylesheet>
    <link href=/resources/css/labsBlog.css rel=stylesheet>
    <link rel="canonical" href='https://0a8600f303b946aa86f048a100400009.web-security-academy.net/?M4rduk'/>
    <title>Reflected XSS in canonical link tag</title>
</head>
```

There it is. You’re in attribute context but inside a href value that contains a full URL.

Notice the quotes around the href are single quotes. And you’re in a link tag, not an a tag. This is a crucial difference. There's nothing to click, and no event fires naturally from user interaction the normal way.

This one is a bit unusual. The exploit relies on injecting an accesskey attribute combined with an event handler. accesskey lets you define a keyboard shortcut that triggers a click event on the element, even one in the <head>.

Try adding this to the URL:

```
/?'accesskey='x'onclick='alert(1)
```

Then look at the source. What does the canonical link tag look like?

```
<head>
    <link href=/resources/labheader/css/academyLabHeader.css rel=stylesheet>
    <link href=/resources/css/labsBlog.css rel=stylesheet>
    <link rel="canonical" href='https://0a8600f303b946aa86f048a100400009.web-security-academy.net/?/?'accesskey='x'onclick='alert(1)'/>
    <title>Reflected XSS in canonical link tag</title>
</head>
```

Good, the injection landed. Now to trigger it press Alt+Shift+X on Windows (that's the keyboard shortcut for accesskey x).

Did the alert fire?

Remember from the lab description:

```
To assist with your exploit, you can assume that the simulated user will press the following key combinations:

ALT+SHIFT+X
CTRL+ALT+X
Alt+X
```

Alt+X worked for me. The exact key combo varies by browser and OS, so that's expected.

Now let’s break down what happened structurally because this one is worth understanding clearly.

Your injection turned the tag into:

```
<link rel="canonical" href='https://0a8600f303b946aa86f048a100400009.web-security-academy.net/?/?'accesskey='x'onclick='alert(1)'/>
```

The first ' closed the href attribute value. Then you injected two new attributes, accesskey='x' which assigned a keyboard shortcut, and onclick='alert(1)' which fires when that shortcut triggers a synthetic click on the element. The remaining ' from the original closing quote closed your onclick value cleanly.

Same pattern as the attribute room we did earlier. Break out of the attribute value with a quote, inject new attributes. The difference here is you couldn’t use an automatic trigger like autofocus/onfocus because it's a link element in the <head>, not a visible interactive element. You needed user interaction via the accesskey shortcut.

This is also why this vulnerability class has lower severity in most bug bounty programs. Requiring user interaction to trigger reduces impact compared to something that fires on page load.

In the URL room, your goal is to control a URL. If you can’t use the javascript: protocol directly, fall back to the principles of the attribute room and inject event handlers, even if they require user interaction.

## Wrapping Up: The Attacker’s Mindset

We’ve toured the four main XSS rooms:

- HTML Body: — The simplest room. If tags aren’t filtered, you can inject them directly.
- Attribute: — You can’t create new tags, but you can break out of a quoted value with “ and inject new attributes and event handlers.
- JavaScript: — You’re already in the code. Break out of the string with quotes or break out of the entire script block with </script>.
- URL: — You control a URL. Use the javascript: protocol, or if it’s a locked-down element, combine attribute injection with an accesskey for triggered execution.

The specific payloads you used, (" autofocus onfocus=alert(1), </script><img src=x onerror=alert(1)>, ';alert(1)//) are just tools. The real skill isn't memorizing the tools, it's understanding the room you're in.

Before you type any payload, ask yourself the three questions:

Where am I?
What’s filtered?
What’s not?

Once you answer those, the correct payload will almost write itself. Master this mindset, and you’ve taken a critical step toward thinking like a web security professional.



---
*Original URL: [https://medium.com/@marduk.i.am/context-is-everything-a-practical-guide-to-xss-eff8d30421df?source=search_post---------45-----------------------------------](https://medium.com/@marduk.i.am/context-is-everything-a-practical-guide-to-xss-eff8d30421df?source=search_post---------45-----------------------------------)*
