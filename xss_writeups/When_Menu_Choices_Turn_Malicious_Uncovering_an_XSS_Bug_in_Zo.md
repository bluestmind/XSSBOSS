# “When Menu Choices Turn Malicious: Uncovering an XSS Bug in Zomato’s Widgets”

> **Author**: Aman Sharma
> **Published**: Dec 12, 2025

---

Member-only story

![Aman Sharma](https://miro.medium.com/v2/da:true/resize:fill:64:64/0*gTsmBWudIxLcZoel)

105

Listen

Share

While poking around the digital infrastructure of popular restaurant discovery platform Zomato, security researcher pr0tagon1st stumbled upon something concerning.

Two of the platform’s widget endpoints, designed to embed restaurant collections on other sites, were carelessly echoing user input. A seemingly innocent URL parameter became a direct pipeline for attackers to inject malicious scripts into the trusted Zomato domain.

free link

![image](https://miro.medium.com/v2/resize:fit:700/1*RZ-_UVzmC4w1-qtPOlCoJA.png)

This wasn’t a flaw in the core website, but in supporting infrastructure — a reminder that attackers often target the least-defended parts of a system. Let’s dissect this finding to understand how a simple oversight in handling URL data can open the door to cross-site scripting (XSS), one of the web’s most persistent threats.

## The Anatomy of a Widget Attack

The vulnerability resided in two widget endpoints: all_collections.php and o2.php. These are helper scripts that external websites can use to display Zomato content.

The researcher found that the city_id and language_id parameters in these scripts did not properly filter or encode HTML and JavaScript input. An attacker could craft a malicious URL like the one below, where the city_id…



---
*Original URL: [https://medium.com/the-first-digit/when-menu-choices-turn-malicious-uncovering-an-xss-bug-in-zomatos-widgets-62f29a9f0b03?source=search_post---------107-----------------------------------](https://medium.com/the-first-digit/when-menu-choices-turn-malicious-uncovering-an-xss-bug-in-zomatos-widgets-62f29a9f0b03?source=search_post---------107-----------------------------------)*
