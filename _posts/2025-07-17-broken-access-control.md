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


 ## Broken Access Control Categories

## 1. Vertical Access Control
This restricts access based on user roles. For example, regular users should not be able to access admin functions or interfaces.

 Common issues:
Unprotected admin functionality: Admin panels or privileged features are accessible without verifying the user’s role.

Access control via client-side parameters: The application relies on values like role=admin in a cookie or URL to control access.

Platform misconfiguration: Servers use headers like X-Original-URL to determine access without proper validation.

Case sensitivity or alternate paths: /admin is protected, but /ADMIN is not — attackers exploit such discrepancies.

 Example labs (from PortSwigger):
Unprotected admin functionality

User role controlled by request parameter


<div align="center">
  <img src="{{ site.baseurl }}/assets/images/b2.png" alt="URL Manipulation Example" width="300" style="border: 1px solid #ccc; border-radius: 8px;">
</div>


## 2. Horizontal Access Control
This ensures that users cannot access each other’s resources, even if they are on the same role level (e.g., two normal users).

 Common issue:
Insecure Direct Object Reference (IDOR): Users can change a parameter like user_id=1002 in a URL or request to access other users’ data.



## 3. Privilege Escalation (Horizontal → Vertical)
Occurs when a low-privileged user exploits weaknesses to gain higher-level permissions, such as accessing admin functions.


A regular user changes their role to "admin" via a hidden parameter or cookie value.

Exploiting misconfigured access checks or missing validation to access restricted features.


## 4. Context-dependent Access Control
The application should validate access based on the context or flow — for instance, only allowing checkout if the user has passed through the cart page.

Attackers directly access endpoints without completing prerequisite steps or workflows.

## 5. Referer or Location-based Control
Some applications wrongly rely on HTTP headers like Referer or Origin to enforce access rules — which can be forged or manipulated.

Assuming that a request is safe because it came from a specific page or location.



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
