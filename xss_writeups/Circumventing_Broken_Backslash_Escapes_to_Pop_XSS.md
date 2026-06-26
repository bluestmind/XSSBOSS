# Circumventing Broken Backslash Escapes to Pop XSS

> **Author**: Justin Ng
> **Published**: Feb 12, 2026

---

![Justin Ng](https://miro.medium.com/v2/resize:fill:32:32/1*EUpms7KIUCS5kDDn3ztsnA.jpeg)

57

Listen

Share

Introduction

Recently, I was testing a non-government web application (admittedly one of the rarer times) and came across a situation where the main page’s search functionality had a non-standardized (but commonly implemented) way of defending against injection attacks. After some quick trial-and-error, I managed to circumvent this defense to pop an XSS on said functionality (which was responsibly disclosed and has since been fixed).

In this blog post, I detail my thought process and step-by-step approach from initial discovery up till successfully proving impact. Additionally, I also write about the importance of providing targeted and actionable recommendations to enable system owners to fix their systems effectively. I hope it will aid readers in learning how to identify similar behaviors for their own testing and responsible disclosures, but more importantly, to gain an insight into the time and effort that goes into bug hunting and making effective recommendations! :)

Discovering the Vulnerability

When testing for injection vulnerabilities, the usual method is to check how special characters are received and rendered by an application. The aim is to identify cases where characters remain un-sanitized throughout the source-to-sink. In this case, the special characters that were tested included single/double quotes and angle brackets etc.

In the search functionality, I entered the following:

```
canary"
```

The web application returned an interesting result:

```
canary\
Total: 0 results found
```

Further testing with payloads containing strings after a double quote yielded the exact same results:

```
Test String:
canary" test123

---

Result:
canary\
Total: 0 results found
```

It appeared that a double quote would be replaced by a backslash character "\" , and any string entered after a double quote would not be reflected on the page. On the surface, it seemed as though backslash was being used to escape special characters. However, the purpose of backslash-escaping is to allow inclusion of the double quote in a string literal. It seemed odd to me that the double quote would be replaced by a backslash itself in the response. Furthermore, the absence of all input after the double quote in the response was not normal behavior of any escaping technique.

To investigate this, I took a look at the DOM of the web application. Using the original payload, the resulting value parameter in the DOM is shown below:

```
<input class="form-control" type="search" name="s" value="canary\" " placeholder="Search">
```

The web application was escaping double quotes using the backslash technique, or at least what seemed like an attempt to use backslashes to escape special characters. Even though my double quote appeared to be “escaped” on the web application, it was in fact still rendered to the DOM and interpreted as part of the DOM itself (even with the backslash), allowing the double quote to close off the value parameter.

On a superficial level, the double quote appeared to be sanitized using backslash-escaping, but in reality, there was no actual sanitization being performed (i.e. the backslash did not sanitize special characters at all). Additionally, special characters were not HTML-encoded too. Therefore, it was possible to circumvent this to run my own JavaScript.

Closing value and Creating New Event Handlers

Since the search term was reflected in the value parameter, one method was to submit a string that could close off the value parameter, followed by creating a new event handler with my own JavaScript. Initially, the following string was submitted:

```
canary" onmouseover=alert()
```

In this payload, the first double quote would close off the value parameter, giving me space to create an onmouseover event handler which would run a proof-of-concept alert() function when the victim moved their mouse across the impacted component of the DOM.

Unfortunately, the first payload ran into a problem:

```
<input class="form-control" type="search" name="s" value="canary\" onmouseover="alert()"" placeholder="Search">
```

As shown in the DOM above, the value parameter was closed off and the onmouseover event handler was successfully created, but an extra double quote remained immediately after the alert() function. This was the original double quote used to close the value parameter. Since I had closed the parameter with my own double quote, it was left dangling and was included within the new onmouseover event, preventing my XSS from triggering. To successfully pop the XSS, I had to figure out a way to get rid of the double quote.

Earlier, I had confirmed that special characters were not HTML-encoded. This included the right angle bracket character. The next payload submitted is shown below:

```
canary" onmouseover=alert()>
```

This payload included a right angle bracket to close off the input element prematurely. The resulting DOM is shown below:

```
<input class="form-control" type="search" name="s" value="canary\" onmouseover="alert()">
"" placeholder="Search"/> "
```

As shown above, adding a right angle bracket successfully closed off the input element, and the dangling double quote was now enclosed within a new pair of double quotes. All text within the new double quotes would be reflected on the web page as plain text. Since the new event handler was successfully created and the double quote issue was solved, hovering the mouse over the affected DOM component could trigger the XSS:

![image](https://miro.medium.com/v2/resize:fit:700/1*7CNihb73RmEtKouq10qCbQ.png)

Digging for Root Cause Analysis

## Get Justin Ng’s stories in your inbox

Join Medium for free to get updates from this writer.

Remember me for faster sign in

Recommended fixes for XSS are pretty standard; it’s usually to either encode data on output or validate input on arrival. The key question is how to go about implementing these recommendations; in other words, the context of the recommendation matters. Is the vulnerability due to JavaScript failing to sanitize special characters properly? Or is it due to server-side code that was not properly written to escape single/double quotes? Knowing this will help in crafting a good recommendation that is targeted for the application’s use case instead of just writing a generic recommendation and leaving the application team to figure out what to do.

To provide an effective recommendation, I had to locate the code responsible for implementing the broken backslash (I was also just really curious to find out what code would give such a broken defense).

Initially, I had the impression that the XSS was a DOM-based Reflected XSS. Attempting to trace the sink meant going through many JavaScript files to locate the problematic code. Without any idea how the sink looked like, it felt like looking for a needle in the haystack after a few while.

At this point, I remembered that I had an instance of Burp with an integrated MCP server lying around in one of my laptops, and decided to let Claude do the heavy lifting. The following is the prompt that I used:

```
I want you to focus on the evidence of html response of the search input fields that show `value=canary\". Your role is to look through all the JavaScript files in the DOM and try to identify the code that is responsible for this backslash escape.
```

While I was expecting a response that pointed to a JavaScript file, Claude gave a surprising reply:

```
...

Analysis Summary
Based on my investigation, here's what's happening with the backslash escape:

The Escaping Chain:

1. User Input: canary"
2. URL Encoding: canary%22
3. Server-Side Processing (WordPress/Ivory Search Plugin):
    • The search query is retrieved: canary"
    • When rendering in HTML attributes, PHP uses esc_attr() or similar function
    • This escapes the double quote as: canary\"
    • When rendering in JavaScript strings, it's further escaped as: canary\\"

...

The Responsible Code:
The backslash escaping is NOT from JavaScript files - it's from server-side PHP. Specifically:

1. WordPress Core Functions like:
    • esc_attr() - escapes HTML attributes
    • esc_js() - escapes JavaScript strings
    • wp_json_encode() - JSON encodes for JavaScript variables

2. Ivory Search Plugin (/wp-content/plugins/add-search-to-menu/) which:
    • Captures the search query from $_GET['s']
    • Passes it through WordPress escaping functions
    • Outputs it in both HTML and JavaScript contexts

...
```

In the response snippet above, Claude identified that the web application was using the WordPress Ivory Search plugin. Based on the JavaScript files that it had analyzed, DOM-based Reflected XSS was ruled out (presumably because no sinks were found in the JavaScript files). This left normal Reflected XSS, which I confirmed by viewing the Source Page and observing that my payload was already part of the page’s HTML.

Evaluating if Source Code Review was Useful

Claude identified that the vulnerability was due to server-side PHP code in the Ivory Search plugin. The next step was to perform source code review to identify the server-side sink. The source code for Ivory Search can be found here.

From its documentation:

Ivory Search is a simple to use advanced WordPress search plugin.

It enhances the default WordPress search and also allows you to create new custom search forms.

With Ivory Search, you can create an unlimited number of search forms and configure each search form individually to customize WordPress search and perform different types of searches on site content.

Display the custom search forms on site header, footer, sidebar or widget area, navigation or menu, on pages, posts, custom post types or anywhere on the site using its shortcodes.

From the description, it was possible that the search functionality in the web application was actually a custom search form created using the plugin. This also meant that it would be unlikely to find the sink from the Ivory Search source code.

True enough, despite scouring through the Ivory Search source code, I could not find the exact file containing the code of the search functionality. However, I did come across a file called class-is-search-form.php that hinted at some customization ability, which allowed me to confirm my hypothesis that the search form was probably customized. Additionally, the code snippet below taken from this file shows how proper escaping was done for a (supposedly, I think) default search form:

```
$search_val = ( $is_form_id && $is_form_id === $args['id'] ) ? get_search_query() : '';
$result .= '<label for="is-search-input-' . esc_attr( $args['id'] ) . '"><span class="is-screen-reader-text">'.__( 'Search for:', 'add-search-to-menu').'</span><input  type="search" id="is-search-input-' . esc_attr( $args['id'] ) . '" name="s" value="' . esc_attr( $search_val ).'" class="is-search-input" placeholder="' . esc_attr( $placeholder_text ) . '" '. esc_attr( $autocomplete ) .' />';
```

As shown, the esc_attr() PHP method was used to escape parameters. Specifically, esc_attr($search_val) was used to escape the search value of the value parameter. It was likely that the custom code was using some other method (or maybe even none at all) to sanitize $search_val in the web application’s search form.

Final Recommendations

While the source code review did not reveal the vulnerability’s root cause, it did give me an understanding of how the search form might look like in the application’s code. Reviewing the class-is-search-form.php file also showed me how proper sanitization looked like in the context of an Ivory Search search form. I could now provide a targeted recommendation to fix the problem (i.e. specify usage of esc_attr() on the server-side PHP, instead of giving a generic recommendation to encode output or validate input). From an application team perspective, this would greatly help in identifying what to fix instead of spending time deducing a solution from vague recommendations:

![image](https://miro.medium.com/v2/resize:fit:700/1*oQbX9UEZ5C8LbIdN0nXU8Q.png)

Between report submission / acknowledgement and receiving the notification above, the fix took less than 2 hours to implement and it was pushed to production within the evening. Had I only given generic recommendations (e.g. encode data but not tell them what to fix and how to do it), it might have taken much longer for the team to identify the problematic code and then hunt for an appropriate solution.

Reflections

This finding would be classified as a simple XSS issue. Nevertheless, every scenario offers an opportunity to learn new things, and these are some key takeaways that I gained from this episode:

- In my day-to-day testing, recommendations are usually made generically as I have no visibility of the application’s source code to pinpoint specific fixes. This instance offered me an opportunity to pursue some source code review where I got to see how encoding was implemented in PHP. In addition to esc_attr() , I learnt about PHP methods such as sanitize_text_field() and sanitize_key() that were also used to mitigate unsafe input. Most importantly, through this server-side code XSS example, my understanding of XSS was broadened to go beyond the usual assumption that frontend JavaScript is the default root cause of XSS.
- I think that AI is fairly trustworthy when it comes to conducting static source code reviews. While usage of AI (such as Claude) to aid in root cause analysis may help to speed things up, it is ultimately an individual judgement to determine the accuracy of the AI’s response. In the case above, Claude was useful in helping to interpret the class-is-search-form.php file. It also successfully identified the context of the backslash technique, but would make mistakes that require human knowledge to “re-guide” it. For example, it wrongly identified that the esc_attr() method escapes quotes but does not escape <and >characters.

Final Note

The vulnerability in this case study is common, and the attack vector is nothing novel. The purpose of this post is not to showcase groundbreaking research, nor is it to present some super complex chain exploit. Instead, it is written to highlight the level of detail (and to emphasize the thought process; notice how I use phrases such as “it could be…” to illustrate my thinking processes) that goes into every step of the discovery process during testing. More often than not, a blog post only presents events on hindsight and does not fully illustrate the cyclical process and many rabbit holes that come with security testing, which gives rise to the impression that hunting for vulnerabilities is easy and making recommendations to fix them is even easier. This could not be further from the truth. I recall spending some time messing around with the “dangling double quotes” issue mentioned earlier, only to make the resulting DOM more complicated. It wasn’t till later when I realised that I could simplify the payload using a right angle bracket to close off the input parameter.

Even as I wrote this post, I have had to review certain parts of the content to ensure that I am being as accurate as possible. This led me to learn new things everytime I did a review (or even go off a tangent such as digging into PHP documentation).

Every exploit (no matter how insignificant) represents a chance to learn something new. In every test, much time is spent researching the environment, the many weird things that always seem oddly specific to the scenario, and troubleshooting seemingly trivial things etc. All of this culminates in new knowledge for the tester, and for me, writing is a way to streamline all this knowledge and consolidate my thoughts from the messiness of fieldwork.

![image](https://miro.medium.com/v2/resize:fit:700/1*UvSeUlGp1-AyFK0kKbYtsA.png)



---
*Original URL: [https://medium.com/@fishp0rridg3/circumventing-broken-backslash-escapes-to-pop-xss-650250276c75?source=search_post---------58-----------------------------------](https://medium.com/@fishp0rridg3/circumventing-broken-backslash-escapes-to-pop-xss-650250276c75?source=search_post---------58-----------------------------------)*
