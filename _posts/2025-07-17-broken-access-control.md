---
layout: post
title: "Broken Access Control"
date: 2025-07-17
categories: [OWASP, Access-Control, PortSwigger]
---

## Table of Contents
- [What Is a Broken Access Control Vulnerability?](#what-is-a-broken-access-control-vulnerability)
- [The Impact and Risk of Broken Access Controls](#the-impact-and-risk-of-broken-access-controls)
- [Examples and Types of Broken Access Control Attacks](#examples-and-types-of-broken-access-control-attacks)
  - [URL Manipulation](#url-manipulation)
  - [Exploiting Endpoints](#exploiting-endpoints)
  - [Elevating User Privilege](#elevating-user-privilege)
- [4 Ways to Prevent Broken Access Control](#4-ways-to-prevent-broken-access-control)
- [Conclusion](#conclusion)
- [References](#references)

---

## What Is a Broken Access Control Vulnerability?

Broken access control vulnerability is a security flaw that allows unauthorized users to access, modify, or delete data they shouldn’t have access to. This vulnerability is considered one of the most critical web application security risks. It occurs when an application fails to properly enforce access controls, allowing attackers to bypass authorization and perform tasks as if they were a legitimate user.

According to [OWASP Top 10](https://owasp.org/Top10/), Broken Access Control is a critical vulnerability and is often found in web applications that do not properly enforce user roles and permissions.



<div align="center">
  <img src="{{ site.baseurl }}/assets/images/b1.png" alt="Broken Access Control" width="300" style="border: 1px solid #ccc; border-radius: 8px;">
</div>



## The Impact and Risk of Broken Access Controls

The risk associated with broken access control is high because it directly affects the confidentiality, integrity, and availability of data. An attacker exploiting this vulnerability can potentially access, modify, or delete any data on the system. This includes user data, system data, application data, and more. The larger the system and the more sensitive the data, the higher the risk.



## Examples and Types of Broken Access Control Attacks

### URL Manipulation

URL manipulation is a straightforward method used by attackers to exploit broken access control vulnerabilities. This involves changing the URL in an attempt to bypass access controls and gain unauthorized access to sensitive data or functionality.

**Example**:  
Consider a URL that includes the user’s ID:  
`http://example.com/user/123`  
An attacker could change the ID to `http://example.com/user/456` to access another user’s data. If the application doesn’t verify access rights before responding, it is vulnerable.


<div align="center">
  <img src="{{ site.baseurl }}/assets/images/b2.png" alt="URL Manipulation Example" width="300" style="border: 1px solid #ccc; border-radius: 8px;">
</div>



### Exploiting Endpoints

Endpoints are the points of interaction between an application and the rest of the system. These could be APIs, microservices, etc. If they are not properly secured, attackers can bypass access control by sending unauthorized requests.

They can find endpoints by scanning, code analysis, or URL guessing. Once found, attackers may extract or modify sensitive data.



### Elevating User Privilege

Privilege escalation involves gaining access to a regular user account, then using access control flaws to gain admin rights.

**Example**: An attacker gains access using a weak password, then changes privileges to admin by modifying requests or exploiting backend logic.

<div align="center">
  <img src="{{ site.baseurl }}/assets/images/b3.png" alt="Privilege Escalation Example" width="300" style="border: 1px solid #ccc; border-radius: 8px;">
</div>


## 4 Ways to Prevent Broken Access Control

### 1. The Principle of Least Privilege

- **Define roles**: Group users (Admin, Editor, Customer).
- **Assign minimum permissions**: Limit actions to role needs.
- **Review regularly**: Revoke or update access when roles change.

### 2. Secure Sessions and Strong Authentication

- **Secure sessions**: Invalidate sessions on logout/inactivity.
- **MFA**: Add multi-factor authentication to reduce account takeover risk.

### 3. Regularly Audit and Review Access

- **Check access rights periodically**.
- **Prune excess permissions**.
- **Monitor suspicious behavior from logs**.

### 4. Handle Errors and Log Intelligently

- **Generic error messages**: Don’t expose sensitive info in responses.
- **Log activities**: Record logins, changes in permissions, and access attempts for incident response.

---

## Conclusion

Broken Access Control is among the most dangerous and prevalent security vulnerabilities in web applications. Even a small oversight in access rules can lead to serious breaches, including unauthorized access, data leakage, and privilege escalation.

To defend against it:

- Apply strict role-based permissions  
- Secure all endpoints  
- Regularly audit your access control mechanisms  
- Log and monitor intelligently

Implementing these strategies not only reduces your attack surface but also builds user trust and complies with data protection standards.

---

## References

- [OWASP Top 10: Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
- [PortSwigger Academy – Access Control Vulnerabilities](https://portswigger.net/web-security/access-control)
- [CWE-284: Improper Access Control](https://cwe.mitre.org/data/definitions/284.html)
