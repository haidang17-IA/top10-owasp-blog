---
title: "Understanding Insecure Deserialization - OWASP Top 10 & PortSwigger Labs"
date: 2025-07-31
layout: post
tags: [owasp, insecure-deserialization, web-security, portswigger]
---

<div style="background-color: #f9f9f9; padding: 20px; border-left: 5px solid #007acc; border-radius: 6px; margin-bottom: 20px;">

<strong>Table of Contents</strong>

<ul>
  <li><a href="#introduction">Introduction</a></li>
  <li><a href="#what-is-insecure-deserialization">What Is Insecure Deserialization?</a></li>
  <li><a href="#why-it-matters">Why It Matters</a></li>
  <li><a href="#how-insecure-deserialization-works">How Insecure Deserialization Works</a></li>
  <li><a href="#common-attack-scenarios">Common Attack Scenarios</a></li>
  <li><a href="#portswigger-lab-example">PortSwigger Lab Example</a></li>
  <li><a href="#detection-techniques">Detection Techniques</a></li>
  <li><a href="#mitigation-and-prevention">Mitigation and Prevention</a></li>
  <li><a href="#summary">Summary</a></li>
  <li><a href="#conclusion">Conclusion</a></li>
  <li><a href="#references">References</a></li>
</ul>

</div>

## Introduction

Insecure Deserialization is a critical vulnerability that can lead to Remote Code Execution (RCE), privilege escalation, authentication bypass, and other severe consequences. It appears in the OWASP Top 10 because of its high impact and frequency in complex applications using object serialization mechanisms.

In this blog, I’ll summarize what I’ve learned from the **PortSwigger Academy** labs related to insecure deserialization, focusing on attack vectors, detection, and practical prevention methods.

---

## What Is Insecure Deserialization?

Deserialization is the process of converting serialized data (often a string or byte stream) back into a data structure or object. Insecure deserialization occurs when an application accepts untrusted input to deserialize without validation or sanitization, allowing attackers to inject arbitrary code or manipulate application logic.

### Example:

```python
import pickle

user_input = request.GET['data']
obj = pickle.loads(user_input)  # Unsafe
```

If `user_input` is controlled by the attacker, arbitrary code can be executed.

---

## Why It Matters

- **Remote Code Execution (RCE):** Deserialize payloads can execute system-level commands.
- **Authentication Bypass:** Attackers can modify user roles or session data.
- **Denial of Service:** Crafted payloads can crash the application.
- **Privilege Escalation:** Manipulating serialized objects can lead to elevated access.

---

## How Insecure Deserialization Works

Attackers exploit the deserialization process by:

1. Crafting a malicious serialized object with executable logic.
2. Sending it to the application where it is blindly deserialized.
3. Gaining access or triggering behavior that compromises the system.

### Technologies Often Affected:

- Java (with `ObjectInputStream`)
- PHP (with `unserialize()`)
- Python (with `pickle`)
- .NET BinaryFormatter

---

## Common Attack Scenarios

### 1. Remote Code Execution

When the object contains executable methods like `__wakeup()`, `__destruct()`, or similar, code can be executed during deserialization.

**Example (PHP):**
```php
O:1:"A":1:{s:4:"data";s:20:"malicious_command();";}
```

### 2. Logic Manipulation

Attacker tampers with serialized session data:

```
s:10:"user_role";s:5:"admin";
```

Result: Escalated privileges

### 3. Replay Attacks

Reusing serialized tokens like JWT or session cookies that contain outdated but valid data.

---

## PortSwigger Lab Example

In the **PortSwigger Lab: Exploiting Insecure Deserialization**, we interact with a vulnerable shopping cart that stores serialized data in a session cookie. By decoding, modifying, and re-encoding it, we can gain admin access.

### Steps:

1. Decode base64 session cookie
2. Identify serialized PHP object
3. Inject payload using tools like `phpggc`
4. Encode and send modified cookie
5. Gain elevated privileges or trigger execution

<div style="text-align: center;">
  <img src="/top10-owasp-blog/assets/images/insecure-deserialization-lab.png" alt="Insecure Deserialization Lab" style="width: 50%; border: 1px solid #ccc; border-radius: 8px;">
  <p><em>Figure: Exploiting a vulnerable deserialization process</em></p>
</div>

---

## Detection Techniques

- **Analyze application behavior:** Look for base64-encoded cookies or request bodies
- **Scan for known patterns:** Serialized object formats, e.g., `O:8:"stdClass"`
- **Use fuzzing tools:** Burp Suite, DeserLab, ysoserial, phpggc
- **Static Code Analysis:** Review usage of `pickle`, `unserialize()`, `BinaryFormatter`, etc.

---

## Mitigation and Prevention

- **Never deserialize untrusted input** unless strictly validated
- **Use safe serialization formats** like JSON instead of binary-based ones
- **Implement integrity checks** (e.g., HMAC signatures)
- **Restrict classes available for deserialization**
- **Use language-specific libraries/tools** to safely deserialize
- **Patch known gadgets** (e.g., avoid insecure libraries)

---


## Conclusion

Insecure Deserialization is a silent but powerful attack vector. With tools like **phpggc**, **ysoserial**, and labs from **PortSwigger**, it's possible to simulate real-world deserialization exploits and understand the importance of handling serialized data safely. Developers must treat all serialized data as untrusted and apply strict validation, signed tokens, and safe formats to avoid critical exploits.

---

## References

- [PortSwigger Academy - Insecure Deserialization](https://portswigger.net/web-security/deserialization)
- [OWASP Insecure Deserialization](https://owasp.org/www-project-top-ten/2017/A8_2017-Insecure_Deserialization)
- [phpggc GitHub](https://github.com/ambionics/phpggc)
- [ysoserial for Java](https://github.com/frohoff/ysoserial)
