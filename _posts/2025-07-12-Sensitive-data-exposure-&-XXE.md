---

layout: post

title: "Sensitive Data Exposure \& XML External Entities (XXE)"

date: 2025-07-12

categories: \[OWASP, Sensitive Data, XXE, PortSwigger]

---



\## Table of Contents



\- \[1. Sensitive Data Exposure](#1-sensitive-data-exposure)

&nbsp; - \[1.1 What is Sensitive Data Exposure?](#11-what-is-sensitive-data-exposure)

&nbsp; - \[1.2 How It Works](#12-how-it-works)

&nbsp; - \[1.3 Exploitation](#13-exploitation)

&nbsp; - \[1.4 Mitigation](#14-mitigation)

\- \[2. XML External Entities (XXE)](#2-xml-external-entities-xxe)

&nbsp; - \[2.1 What is XML External Entities (XXE)?](#21-what-is-xml-external-entities-xxe)

&nbsp; - \[2.2 How It Works](#22-how-it-works)

&nbsp; - \[2.3 Exploitation](#23-exploitation)

&nbsp; - \[2.4 Mitigation](#24-mitigation)

\- \[3. Conclusion](#3-conclusion)

\- \[4. References](#4-references)



---



\## 1. Sensitive Data Exposure



\### 1.1 What is Sensitive Data Exposure?



Sensitive Data Exposure is a vulnerability where applications accidentally expose sensitive user data, such as passwords, credit card numbers, session tokens, or personal identifiers (PII), due to insecure storage, transmission, or processing. It ranked highly in the \[OWASP Top 10](https://owasp.org/www-project-top-ten/) for its widespread impact.



\### 1.2 How It Works



This vulnerability often arises due to:



\- Using plain HTTP instead of HTTPS.

\- Storing credentials or tokens in plain text.

\- Returning sensitive information in response bodies, headers, or cookies.

\- Inadequate encryption or no encryption of sensitive data.



\### 1.3 Exploitation



\#### Common attack methods:



\- \*\*Intercepting network traffic\*\*: If HTTPS is not enforced, attackers can sniff data packets.

\- \*\*Accessing backups or poorly secured files\*\*.

\- \*\*Leaking information in responses\*\* to endpoints.



\#### Example:



```bash

GET /api/user/details HTTP/1.1

Host: vulnerable.com

```



Response:



```json

{

&nbsp; "username": "admin",

&nbsp; "password": "admin123",

&nbsp; "credit\_card": "4111-1111-1111-1111",

&nbsp; "token": "abcdef123456"

}

```



This response leaks credentials and card data in clear text.



\### 1.4 Mitigation



\- Enforce HTTPS site-wide using strong TLS configurations.

\- Use strong encryption (AES-256) for data at rest.

\- Do not store sensitive data unless absolutely necessary.

\- Mask sensitive output (e.g., show only last 4 digits of a card).

\- Apply secure cookie flags (`Secure`, `HttpOnly`, `SameSite`).

\- Perform regular audits for data exposure and leaks.



---



\## 2. XML External Entities (XXE)



\### 2.1 What is XML External Entities (XXE)?



XXE is a vulnerability that occurs when an XML input containing a reference to an external entity is processed by a weakly configured XML parser. This can allow attackers to read local files, perform SSRF, or cause denial of service.



\### 2.2 How It Works



When XML parsers accept user input and support DTDs (Document Type Definitions), attackers can define their own external entities.



\#### Example DTD declaration:



```xml

<!DOCTYPE foo \[

&nbsp; <!ELEMENT foo ANY >

&nbsp; <!ENTITY xxe SYSTEM "file:///etc/passwd">

]>

```



The XML parser replaces `\&xxe;` with the contents of the referenced file.



\### 2.3 Exploitation



\#### Payload example:



```xml

<?xml version="1.0" encoding="UTF-8"?>

<!DOCTYPE root \[

&nbsp; <!ENTITY xxe SYSTEM "file:///etc/passwd">

]>

<root>

&nbsp; <data>\&xxe;</data>

</root>

```



When processed by a vulnerable backend, the response may include the contents of `/etc/passwd`.



\#### Impact:



\- \*\*File disclosure\*\*

\- \*\*SSRF\*\*: if URL-based entities are used

\- \*\*Denial of Service\*\* using Billion Laughs attacks



\### 2.4 Mitigation



\- Disable DTDs entirely (`disallow-doctype-decl`) in XML parsers.

\- Disable external entities and inline parameter entities.

\- Use safe libraries:

&nbsp; - Java: set features on `DocumentBuilderFactory`

&nbsp; - Python: use `defusedxml`

\- Prefer JSON over XML for data transmission.

\- Sanitize and validate XML inputs strictly.



---



\## 3. Conclusion



Sensitive Data Exposure and XML External Entities (XXE) are two critical vulnerabilities in modern web applications. Both stem from weak configurations and a lack of secure practices in data handling or XML parsing.



To stay secure:



\- Always encrypt and restrict access to sensitive data.

\- Treat all user-supplied XML as untrusted.

\- Regularly review and update your application’s security settings.



Implementing secure development practices and proper input/output handling can effectively mitigate these threats.



---



\## 4. References



\- \[OWASP Top 10 – A03:2021 – Sensitive Data Exposure](https://owasp.org/Top10/A03\_2021-Sensitive\_Data\_Exposure/)

\- \[OWASP Top 10 – A05:2021 – Security Misconfiguration (XXE)](https://owasp.org/Top10/A05\_2021-Security\_Misconfiguration/)

\- \[PortSwigger Web Security Academy – XXE](https://portswigger.net/web-security/xxe)

\- \[PortSwigger Web Security Academy – Sensitive Data Exposure](https://portswigger.net/web-security/secure-data-storage)

\- \[XML Security Best Practices - OWASP](https://owasp.org/www-project-xml-security/)



---



&nbsp;This blog is part of my hands-on journey with \[PortSwigger Web Security Academy](https://portswigger.net/web-security).  

&nbsp;Repository: \[owasp-top10-labs](https://github.com/haidang17-IA/owasp-top10-labs)  

&nbsp;Blog site: \[top10-owasp-blog](https://haidang17-ia.github.io/top10-owasp-blog/)



