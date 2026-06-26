# Stop Guessing XSS Payloads

> **Author**: Marduk I Am
> **Published**: Apr 8, 2026

---

## Identify Context in 3 Steps

![Marduk I Am](https://miro.medium.com/v2/resize:fill:32:32/1*zFQ8mbLyUwfh4gnFly7u0w.png)

14

1

Listen

Share

![image](https://miro.medium.com/v2/resize:fit:700/1*9e8PE-CU0ovN5Twvk59kSg.png)

## Overview

This article builds directly on my previous write-up, Context Is Everything: A Practical Guide to XSS, where we broke down how different XSS contexts work and how they affect what payloads are possible.

In this article, we’re taking that idea further. Moving from understanding context to quickly identifying it on real targets.

We’ll focus on three core contexts you’ll encounter in server-rendered responses:

- HTML body
- Attribute context
- JavaScript context

There’s a fourth (URL-based contexts), but that introduces additional complexity and deserves its own deep dive. I will cover that topic in a follow-up.

If the first article was about understanding the different contexts, this one is about speed. When you’re working on a real target, you don’t have time to slowly analyze everything. You need a quick, repeatable way to identify where your input lands and what’s possible.

This is that process.

## Introduction

Given a live target with a reflection, how do you quickly identify which context you’re in and what’s filtered? The process has three steps. Stop trying to guess payloads. Try to understand how the browser is interpreting your input.

Every time you find a reflection, before you touch a payload list, do these three things in order.

## Step 1: Find every place your input appears

In a search bar, send a unique string that won’t naturally appear on the page. This is why I use M4rduk. It’s short and unlikely to appear naturally in the page.

Find (Ctrl-f) every single place your string appears. There’s often more than one, as you may have seen in labs.

### 📓 NOTE

- Search for your unique string IN page source (Ctrl+u), NOT dev tools inspector. Page source shows you the raw HTML the server sent. Inspector shows you the DOM after JavaScript has modified it. For finding injection contexts you want the raw source first.

## Step 2: For each reflection, identify the context

Look at what’s immediately surrounding your input.

Ask yourself:

- Is it between tags as visible text? HTML body.
- See Work-through 1 (below)

```
<p>Search results for M4rduk</p>
```

Is it inside a tag, within an attribute value? Attribute context.

- Note whether it’s wrapped in " or ' or nothing at all.
- See Work-through 2 (below)

```
<input type="text" name="search" value="M4rduk">
```

Is it inside a <script> block? JavaScript context.

- Is it in a string? What kind of quotes?
- See Work-through 3 (below)

```
<script>
  var query = "M4rduk";
  doSearch(query);
</script>
```

## Step 3: Probe what’s filtered before throwing payloads

This is the step most people skip and it’s the most important one. Send these characters one at a time and check what happens to each in the source:

```
"
'
<
>
/
\
```

For each one ask:

- Did it pass through unchanged?
- Did it get HTML encoded?
- Did it get double-encoded?
- Did it get escaped with a backslash?
- Did it get stripped entirely?

The answers tell you exactly which escape routes are open and which are blocked. You’re not guessing, you’re reading the specific situation in front of you.

## Work-through 1

### Step 1: Find your input

In a search bar, search for your unique string: M4rduk

This is a very common reflection pattern. Your search string appears directly on the page, not inside an HTML attribute. Something like:

```
There are 0 search results for M4rduk
```

### Step 2: Identify the context

Open the page source and search for your string. You should see something similar to:

```
<p>There are 0 search results for M4rduk</p>
```

There are no attributes to break out of. You are directly inside HTML text content.

### Step 3: Probe for what’s filtered

At this point you will want to see if tags are directly injectable. For this I use a simple <i> tag. Search for: <i>M4rduk</i>

In the page source check to see:

- If you see your angle brackets are encoded as &lt; and &gt;:

```
<p>There are 0 search results for &lt;i&gt;M4rduk&lt;/i&gt;</p>
```

- Tag injection is blocked. Move on to your next reflection in the page source and begin again.

2. If you see <i>M4rduk</i> unchanged:

```
<p>There are 0 search results for <i>M4rduk</i></p>
```

- Tag injection is open. Proceed to testing the rendered page.

On the rendered page, you can confirm:

- If you see plain text with no italics (the <i> tags appear as literal characters):

```
There are 0 search results for M4rduk

*or*

There are 0 search results for <i>M4rduk</i>
```

- Tags are encoded or stripped. No injection possible.

2. If you see italicized text:

```
There are 0 search results for M4rduk
```

- The <i> tag was interpreted by the browser
- HTML injection works

### 📓 NOTE

- If <i> doesn't work, cycle through other tags (<h1>, <b>) in Burp. Just because one tag gets blocked doesn't mean others won't.

## Work-through 2

### Step 1: Find your input

Here’s a real example of how a reflection inside a tag, within an attribute value, may play out.

## Get Marduk I Am’s stories in your inbox

Join Medium for free to get updates from this writer.

Remember me for faster sign in

Search for your unique string. Then pull up the page source, finding everywhere your string lands.

### Step 2: Identify the context

You notice you’re in an attribute context of an <input> tag.

```
<input type="text" name="search" value="M4rduk">
```

You also notice the attribute is using double quotes, ", to surround your search string.

Now you probe.

### Step 3: Probe for what’s filtered

Send a " to try to break out of the attribute: M”4rduk

- If you see &quot; or &#34;:

```
<input type="text" name="search" value="M&quot;4rduk">
```

- quotes are encoded, attribute escape is blocked

2. If you see \”:

```
<input type="text" name="search" value="M\"4rduk">
```

- quotes are escaped, attribute escape is blocked

3. If you see ":

```
<input type="text" name="search" value="M"4rduk">
```

- Goes through unchanged. You can break out, attribute injection is open.
- From here you can start crafting your payload, starting with a double quote.

At this point, if your double quote comes back encoded or escaped, this attribute is not escapable with that delimiter. Move on to your next reflection in the page source and begin again.

However, if you can escape the attribute, you still need to close the <input> tag before your payload will work.

You have already established you can break out of the attribute with a double quote. Try sending it again, but append a closing angle bracket to try to escape the <input> tag: M”>4rduk

- If you see “&gt;:

```
<input type="text" name="search" value="M"&gt;4rduk">
```

- angle brackets encoded, can’t inject new tags even if you break out of the attribute

2. If you see “>:

```
<input type="text" name="search" value="M">4rduk">
```

- Goes through unchanged. You can inject tags after breaking out
- Whatever payload you craft will have to begin with “>. Something like:

```
"><img src=x onerror=alert(document.cookie)>
```

## Work-through 3

### Step 1: Find your input

Here is a scenario where you may see your reflection within a Javascript context. In the real world the script you see may be a little more complex, but the thought process is still the same.

Same as previously, find all reflections of your search string in the page source.

### Step 2: Identify the context

In the page source find your search string:

```
<script>
  var query = "M4rduk";
  doSearch(query);
</script>
```

You’re inside a script block. HTML injections won’t help you here because the browser is parsing Javascript, not HTML. You need to think in Javascript syntax.

You also notice your search string is encased in double quotes ".

Now to probe.

### Step 3: Probe for what’s filtered

Send a " to try to break out of the string: M4rduk"

In the page source:

- If you see your double quote escaped with a backslash:

```
<script>
  var query = "M4rduk\"";
  doSearch(query);
</script>
```

- Quotes are escaped. String breakout is blocked. Move on to your next reflection in the page source and begin again.

2. If you see M4rduk” unchanged:

```
<script>
  var query = "M4rduk"";
  doSearch(query);
</script>
```

- The quote breaks out of the string. JavaScript injection is open.

If the quote is unescaped, try closing the statement with a semi-colon, ;, and injecting a new one: M4rduk”;alert(1)//

```
<script>
  var query = "M4rduk";alert(1)//";
  doSearch(query);
</script>
```

- “ — closes the string
- ; — ends the original statement
- alert(1) — is your injected code
- // — comments out the rest of the original line so you don’t break the script’s syntax.

The key difference from attribute context: you don’t need < or >. You're already inside JavaScript. Your goal is to break out of the string and into executable code.

### 📓 NOTE:

- On the rendered page (browser console):

- Unlike HTML injection, JavaScript injection won’t show visible changes on the page. Open the browser’s developer console (F12) and look for:
- If you see a JavaScript syntax error:

```
Uncaught SyntaxError: missing ) after argument list
```

- Your payload broke the JavaScript. Injection may still be possible with fine-tuning.
- If you see no errors or your test payload executes, injection works.

## Conclusion

XSS isn’t about memorizing payloads. It’s about understanding context.

Every reflection tells you something. The surrounding code tells you how the browser will interpret your input. The filtering tells you what’s allowed and what isn’t.

If you slow down and follow the process:

- Find
- Identify
- Probe

You stop guessing and start making informed decisions.

That’s the difference between randomly throwing payloads at a target and actually understanding why something works. Once you can consistently identify context and filtering, payloads become the easy part.

This process works for server-side reflections, but modern applications often involve heavy client-side rendering. That introduces a new layer — JavaScript-driven contexts — which require a slightly different approach.

In the next write-up, I’ll break down how to manually inspect JavaScript files to uncover hidden XSS opportunities that never appear in the raw HTML.

marduk-i-am | web security notes



---
*Original URL: [https://medium.com/@marduk.i.am/stop-guessing-xss-payloads-881cad409624?source=search_post---------15-----------------------------------](https://medium.com/@marduk.i.am/stop-guessing-xss-payloads-881cad409624?source=search_post---------15-----------------------------------)*
