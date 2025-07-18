---
title: "Understanding SQL Injection - OWASP Top 10 & PortSwigger Labs"
date: 2025-07-10
layout: post
tags: [owasp, sql-injection, web-security, portswigger]
---

## Introduction

SQL Injection (SQLi) is one of the most common and dangerous vulnerabilities in web applications. It allows attackers to interfere with the queries that an application makes to its database. This blog post is a detailed summary of my hands-on learning with **PortSwigger Academy**, focusing on SQLi types, payloads, and real-world examples. All labs mentioned here have been tested and documented [on this GitHub repository](https://github.com/haidang17-IA/owasp-blog).

---

## Why Is SQL Injection a Major Security Threat?

SQLi allows attackers to bypass basic authentication mechanisms to access your database directly and extract data. Once inside, they steal, modify, and delete your business-sensitive data, such as login credentials, customer records, and financial transactions.

It’s hard to trace SQLi attacks as they alter code logic, which makes detection and prevention difficult. They can also install malware to take the full system controls and cause website defacement, complete system failure, and ransomware infections. They can steal data, encrypt data, demand ransom, or expose your sensitive business data to the public to cause reputational damage.
---
## How Do SQL Injection Attacks Work?
Let’s understand this with an example. This is a vulnerable logic form of an application:

SELECT * FROM users WHERE username = ' " + userInput + " ' AND password = ' " + passwordInput + " ';

Suppose an attacker inputs these commands to change the logic:

Username: ‘admin’ - -

Password: anything

The query now becomes:

SELECT * FROM users WHERE username = 'admin’ - -’ AND password = 'anything';

When you use ‘- -’ in an SQL command, it means you are using a comment operator to ignore everything that follows it. It allows the attacker to log in as the ‘admin’ user and proceed without entering the password. Result? They gain unauthorized access to the app’s database and execute their malicious intent.


---

## 1. Authentication and Logic Bypass

** How it works:**  
To carry out a classic or in-band SQL injection attack, the attacker finds and exploits poorly created SQL queries of an application. They insert malicious SQL statements into input fields to alter the original logic of the query. And when they are successful at this, they can:

-Bypass authentication to gain access to the application
-Manipulate or steal confidential information

```

**How to Detect:**

Look for suspicious or unusual app activities and signs that could indicate the presence of a classic SQLi attack.

-Abnormal app behavior
-Unexpected errors: If an app returns database errors, such as invalid SQL statements, syntax errors, etc., someone could be altering the app’s query logic.
-Suspicious SQL commands: If you find suspicious SQL commands in your application and database logs, this could be SQLi. Look for SQL statements with special characters, such as UNION SELECT, ‘  OR  ’1’ = ‘1’ to detect SQLi attacks.


```
<div style="text-align: center;">
  <img src="/top10-owasp-blog/assets/images/sql-diagram.png" alt="SQL Injection Diagram" style="width: 40%; border: 1px solid #ccc; border-radius: 8px;">
  <p><em>Figure 1: SQL Injection workflow</em></p>
</div>

---


**Prevention:**  
- Always use **parameterized queries** (`prepared statements`)
- Avoid directly embedding user input in SQL
- Implement proper authentication and error handling
- Least privilege access

---

## 2. Blind SQL Injection Attack

A blind SQL injection attack occurs when the attacker injects malicious SQL commands into database fields “blindly,” meaning without directly obtaining the output of the command from the application, unlike classic SQLi. Instead, they look for indirect clues, such as HTTP responses, response times, app behavior, etc., to infer the result of the command. This is why they are also called inferential SQL injection. It is of two types – time-based SQLi and boolean/content-based SQLi.

Example: A hacker may inject conditional statements to check if the database contains a specific piece of information based on how the app responds.

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

**Detection:**  
-Monitor logs: Set up security monitoring systems to track application logs.
-Check app behavior

**Prevention:**  
-Prepared statements/parameterized queries
-Error handling
-Restrict access
-Continuous monitoring
---



## 3. Time-Based Blind SQL Injection

**Concept:**  
Time-based blind SQL injection is a type of blind/inferential SQL injection. The attacker manipulates an app’s queries to cause delays in response deliberately. They depend on the app response time to decide whether their query is valid or invalid.

**Payload Example:**  
```sql
' OR 'a'='a
```
<div style="text-align: center;">
  <img src="/top10-owasp-blog/assets/images/3.png" alt=" " style="width: 20%; border: 1px solid #ccc; border-radius: 8px;">
  <p><em>Figure 1: SQL Injection workflow</em></p>
</div>

```


**How to Detect and Prevent Time-based Blind SQLi:**  
Detection: To detect time-based blind SQL injection, use the same methods that we discussed in blind SQL injection:
-Analyze response times
-Check logs
-Behavior analytics
-Vulnerability scanners

```sql
SELECT * FROM orders WHERE user_id = '$uid' AND paid = 1
```

If the attacker makes `paid = 1` always true via SQLi, the system delivers the product for free.

---
** Prevention : **
-Validate inputs
-Parameterized queries
-Test regularly
-Update
-Limit access
-Use advanced tools
---


## 4. Error-Based SQL Injection

Error-based SQL injection is a type of classic/in-band SQL injection on applications and databases. It focuses on finding and exploiting error messages to determine the database details.
- Use `UNION SELECT`
- Discover column count via trial/error
- Dump data from another table

**Payload:**
```sql
' UNION SELECT username, password FROM users --
```

<div style="text-align: center;">
  <img src="/top10-owasp-blog/assets/images/4.png" alt=" " style="width: 20%; border: 1px solid #ccc; border-radius: 8px;">
  <p><em>Figure 1: SQL Injection workflow</em></p>
</div>

```

**How to Detect and Prevent:**  
Detection: To detect error-based SQL injections, resolve them immediately, and limit the damages:
- Unexpected error messages 
- Suspicious logs
- Scan for vulnerabilities
-Penetration testing

---

Prevention: Prevent error-based SQLi attacks from harming your organization in terms of finances, reputation, and customer trust with these tips:
-Disable error messages
-Log error messages safely
-Use WAFs
-Audit and update

---


## 5.  Union-Based SQL Injection

Union-based SQL injections unite the outputs of multiple queries to form a single output using the SQL command – UNION. This merged output now is returned as an HTTP response, which is used to retrieve data from different tables under the same database. Hackers use this data to attack your database and application.

**How it Works:**  
First, an intruder tries identifying how many columns are there in the target database query. Until they see an error, the intruder keeps submitting different variations of this command to find the column count:

```sql
' UNION SELECT NULL, version() --
' UNION SELECT NULL, database() --
```

**How to Detect and Prevent :**  

Detection: Detecting a union-based SQL injection lets you combat and neutralize the threat before it becomes a full-blown attack :

- Analyze logs
- Track page behavior
- TTest: Conduct security tests, such as penetration testing, on your application to understand if it has SQLi vulnerabilities.

**Prevention:**  
-Use prepared statements
-Restrict database permissions
-Validate inputs
-Use advanced tools

---

## 6. Out-of-Band SQL Injection

Out-of-band SQL injection is not so common, but when it happens, it can impact your organization’s reputation and finances.

**How it Works:**  
When an attacker injects harmful SQL commands into the database, it triggers or forces the database to connect to an external server that they have control over. This way, the attacker retrieves sensitive information such as user/system credentials, and analyzes and exploits it to control the database.


**How to Detect and Prevent :**

- **Detection:**  
  
-Monitor external traffic
-Log database
-IDS: Use intrusion detection systems (IDS) to detect the presence of unauthorized access attempts to an external server.



**Prevention:**  
-Use allowlists: Create an allowlist of authorized IP addresses and domains that your data must communicate with, rejecting all others.
-Disable external communications

---

## 7. Second-Order SQL Injection

Second-order SQL injection is an advanced cyber threat where an attacker deploys and stores a malicious SQL-based payload in a database. This payload would not execute immediately after. Instead, if a different SQL query processes this stored payload, the payload will be triggered.

**How it Works:**  
First, the attacker will inject the SQL payload into an app’s field that saves data in its database, such as user registration, profile updates, comments, etc. Next, the payload will sit there as if it were dormant, doing no harm, operation disruptions, or errors.
```


**How to Detect and Prevent:**  

Detection: Here are some of the ways to detect second-order SQL injection, so you can prioritize and remediate them faster:

- Code audits
-Monitor your database
-Check interactions


---
Prevention: Consider these methods to prevent second-order SQLi attacks and avoid reputation and financial losses:
-Sanitize inputs
-Test regularly: Perform regular testing on your application, such as penetration testing, vulnerability assessments
-Limit access: Use access controls, such as the principle of least access, zero trust, and role-based access

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

