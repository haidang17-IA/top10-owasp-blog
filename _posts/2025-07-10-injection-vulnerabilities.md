---
title: "Understanding SQL Injection - OWASP Top 10 & PortSwigger Labs"
date: 2025-07-10
layout: post
tags: [owasp, sql-injection, web-security, portswigger]
---

## Introduction

SQL Injection (SQLi) is one of the most common and dangerous vulnerabilities in web applications. It allows attackers to interfere with the queries that an application makes to its database. This blog post is a detailed summary of my hands-on learning with **PortSwigger Academy**, focusing on SQLi types, payloads, and real-world examples. All labs mentioned here have been tested and documented [on this GitHub repository](https://github.com/haidang17-IA/owasp-blog).

---

## 1. Authentication and Logic Bypass

**🛠️ How it works:**  
Attackers insert SQL into login fields to trick the system into granting access without valid credentials.

**Example Payload:**  
```sql
' OR 1=1 --
```
<div style="text-align: center;">
  <img src="/top10-owasp-blog/assets/images/sql-diagram.png" alt="SQL Injection Diagram" style="width: 40%; border: 1px solid #ccc; border-radius: 8px;">
  <p><em>Figure 1: SQL Injection workflow</em></p>
</div>

---
**Vulnerable Code:**  
```php
$query = "SELECT * FROM users WHERE username = '$user' AND password = '$pass'";
```

**What happens:**  
The condition `OR 1=1` always returns true. The SQL query becomes logically valid, skipping authentication entirely.

**Real Case:**  
Seen in outdated PHP sites or custom admin panels that directly include form input in SQL queries.

**Prevention:**  
- Always use **parameterized queries** (`prepared statements`)
- Avoid directly embedding user input in SQL
- Implement proper authentication and error handling

---

## 2. Retrieving Hidden Data

**Goal:**  
Explore data that exists in the database but is not normally displayed to users.

**Payload Strategy:**  
Inject logic that forces the application to return extra records.

```sql
' OR 1=1 ORDER BY 1 --
```

or

```sql
' UNION SELECT username, password FROM users --
```
<div style="text-align: center;">
  <img src="/top10-owasp-blog/assets/images/2.png" alt=" " style="width: 40%; border: 1px solid #ccc; border-radius: 8px;">
  <p><em>Figure 1: SQL Injection workflow</em></p>
</div>

```

**Explanation:**  
By using `UNION`, attackers can append the output of a second query to the original result.

**Lesson Learned:**  
Many applications display part of the database unknowingly — especially when output is not filtered or restricted.

---

## 3. Subverting Application Logic

**Concept:**  
Instead of just logging in, the attacker changes how the application *behaves*. For instance, skipping payment or admin checks.

**Payload Example:**  
```sql
' OR 'a'='a
```

**Scenario:**  
A purchase validation query might be:

```sql
SELECT * FROM orders WHERE user_id = '$uid' AND paid = 1
```

If the attacker makes `paid = 1` always true via SQLi, the system delivers the product for free.

---

## 4. Retrieving Data from Other Tables

**Advanced SQLi:**  
Once attackers confirm SQL injection is possible, they pivot to reading other tables like `users`, `cards`, or `secrets`.

**Technique:**  
- Use `UNION SELECT`
- Discover column count via trial/error
- Dump data from another table

**Payload:**
```sql
' UNION SELECT username, password FROM users --
```

**Protection:**  
- Implement least privilege for database accounts  
- Deny access to system tables  
- Sanitize every input, not just login forms

---

## 5. Examining the Database

**Why?:**  
Understanding the database helps attackers craft better queries.

**Useful Payloads:**  
```sql
' UNION SELECT NULL, version() --
' UNION SELECT NULL, database() --
```

**Goal:**  
- Find the DBMS (MySQL, PostgreSQL, etc.)
- Identify current database and schema
- Tailor payloads accordingly

**Tip:**  
Some databases like Oracle or MSSQL require different syntax or encodings.

---

## 6. Blind SQL Injection

**Definition:**  
Occurs when an application doesn't return errors but still processes injected SQL. Results are inferred from behavior.

**Exploitation Methods:**

- **Boolean-based:**  
  ```sql
  ' AND 1=1 --
  ' AND 1=2 --
  ```
  Observe response differences.

- **Time-based:**  
  ```sql
  ' OR IF(1=1, SLEEP(5), 0) --
  ```
  Causes delay if true.

**Real-World Use:**  
APIs and modern apps often hide errors but are still vulnerable — blind SQLi is the stealthy way to exploit them.

---

## 7. Second-Order SQL Injection

**What is it?:**  
Injection that occurs *later*, not at the point of input. Data is stored in the DB and used in future queries.

**Scenario:**  
A user signs up with the name:
```
Robert'); DROP TABLE users; --
```
Nothing breaks now. But later, when the app builds a query using this data, it fails or becomes vulnerable.

**Mitigation:**  
- Sanitize input not just at entry but before *every* DB use  
- Review all places where user input is reused

---

## Summary

SQL Injection is a critical vulnerability with deep impact potential — from login bypass to full database compromise. Through **PortSwigger Labs**, I practiced exploiting and mitigating different SQLi scenarios. The key takeaways:

- **Never trust user input**
- **Always use prepared statements**
- **Test regularly with tools like Burp Suite**
- **Understand how your queries are built**

You can find my detailed lab walkthroughs, payloads, and source code on [my GitHub blog repo](https://github.com/haidang17-IA/owasp-blog).

---

Conclusion
Working through the PortSwigger SQL Injection Labs helped me deeply understand both exploitation techniques and real-world mitigations. Each lab focuses on specific scenarios, from simple login bypass to advanced out-of-band attacks. These exercises emphasize why user input should never be trusted and how writing secure code is crucial in defending against Injection vulnerabilities.

## References

- [PortSwigger Web Security Academy](https://portswigger.net/web-security/sql-injection)
- [OWASP SQL Injection Guide](https://owasp.org/www-community/attacks/SQL_Injection)

