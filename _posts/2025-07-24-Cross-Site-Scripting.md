---
title: "Cross-Site Scripting (XSS): OWASP Top 10 & Real-World Exploitation"
date: 2025-07-31
layout: post
tags: [OWASP, Web Security, XSS]
---

<!-- Table of Contents -->
<div style="flex: 1; background-color: #f9f9f9; padding: 20px; border-left: 5px solid #007acc; border-radius: 6px;">
  <strong>Table of Contents</strong>
  <ul>
    <li><a href="#1-cross-site-scripting-xss">1. Cross-Site Scripting (XSS)</a>
      <ul>
        <li><a href="#11-what-is-cross-site-scripting-xss">1.1 What is Cross-Site Scripting (XSS)?</a></li>
        <li><a href="#12-how-it-works">1.2 How It Works</a></li>
        <li><a href="#13-exploitation">1.3 Exploitation</a></li>
        <li><a href="#14-mitigation">1.4 Mitigation</a></li>
      </ul>
    </li>
    <li><a href="#2-conclusion">2. Conclusion</a></li>
    <li><a href="#3-references">3. References</a></li>
  </ul>
</div>

---

## What is Cross-Site Scripting (XSS)?

Cross-Site Scripting (XSS) is a client-side code injection vulnerability that allows attackers to inject malicious scripts into web pages viewed by other users. When executed in the victim’s browser, these scripts can steal cookies, session tokens, sensitive data, or perform actions on behalf of the user.

XSS is included in the OWASP Top 10 due to its high frequency and impact.

---

## Types of XSS

### 1. Stored XSS

**Definition**: Stored XSS occurs when malicious scripts are permanently saved on the target server (e.g., in a database, comment section, forum post). Any user who accesses the affected page will automatically execute the malicious code.

**How it works**:  
Attacker submits malicious JavaScript into an input field that gets stored in the application’s database. When another user loads the page, the stored script is included in the page’s HTML and executed by the browser.

**Example payload & Mitigation**:
- _Payload_: `<script>alert('XSS')</script>`
- _Mitigation_:
  - Sanitize and validate all user inputs.
  - Apply a strict Content Security Policy (CSP).
  - Encode output contextually (HTML, JS, URL).

---

### 2. Reflected XSS

**Definition**: Occurs when malicious scripts are embedded in a URL or request and reflected back to the browser in the server’s response without proper sanitization.

**How it works**:  
Attacker crafts a malicious link containing JavaScript code in a parameter. Victim clicks the link and sends a request to the vulnerable application, which reflects the malicious input in its response.

**Example payload & Mitigation**:
- _Payload_: `https://example.com/search?q=<script>alert('XSS')</script>`
- _Mitigation_: Same as Stored XSS.

---

### 3. DOM-Based XSS

**Definition**: DOM XSS arises when client-side JavaScript modifies the page DOM using data from an untrusted source without proper validation or sanitization.

**How it works**:  
JavaScript reads data from `document.location`, `document.referrer`, etc., and injects it into the DOM without checks.

**Example**:
```javascript
document.body.innerHTML = location.hash.substring(1);


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


