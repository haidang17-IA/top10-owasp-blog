---



title: "Write-up: Broken brute-force protection, multiple credentials per request"



date: 2025-08-07



layout: post



tags: \[owasp, Broken brute-force, web-security, portswigger]



---





\### Lab Description



This lab’s login mechanism is vulnerable because the server allows multiple passwords to be submitted for a single username in one HTTP request. This bypasses most rate-limiting or brute-force protection mechanisms, enabling an attacker to attempt many passwords at once and quickly guess the correct one.



The goal is to brute-force the password for the carlos user and log in as them.



---



\## Understanding the Logic



Normally, brute-force protection detects repeated failed login attempts from the same IP or for the same account and temporarily blocks them. However, in this lab:



-The server accepts JSON arrays for the password parameter.



-It processes each password in the array sequentially, stopping when a match is found.



-Because all password attempts are sent in one request, traditional per-request lockout is bypassed.



-Once the correct password is found, the server issues a valid session ID for the target account in the HTTP response.



This means we can:



-Send many passwords in a single login request.



-Detect the successful login from the response.



-Steal the target user’s session and take over their account.



\## Steps to Exploit

\### Step 1 — Identify the login request

-Log in with your own credentials (wiener:peter) and intercept the request in Burp Suite.

-Locate the POST /login request with JSON body:



```

{

&nbsp; "username": "carlos",

&nbsp; "password": "test"

}

```


<div style="text-align: center;">

&nbsp; <img src="/top10-owasp-blog/assets/images/brw1.png" alt="POST/LOGIN body" style="width: 40%; border: 1px solid #ccc; border-radius: 8px;">

&nbsp; <p><em>Figure 1: </em> Tested the cookie value </p>

</div>





\### Step 2 — Test multiple passwords in one request



-Modify the password parameter to be an array of strings:

```
{

&nbsp; "username": "carlos",

&nbsp; "password": \["123456", "password", "12345678"]

}

```

-Send the request to see if the server accepts it without error.



\### Step 3 — Perform brute-force attack

-Load a large list of common passwords (e.g., top-100.txt) or Authentication lab passwords in PortSwigger  into the array.





<div style="text-align: center;">

  <img src="/top10-owasp-blog/assets/images/brw2.png" alt=" Password List " style="width: 40%; border: 1px solid #ccc; border-radius: 8px;">

  <p><em>Figure 2: </em>  </p>

</div>





-Use Burp Repeater or Intruder to send the payload.



-One of the attempts will trigger a successful login in the server’s processing.



\### Step 4 — Extract the session ID

-In the Raw HTTP response of the successful login request, check the Set-Cookie header:

```

Set-Cookie: session=YOUR\_SESSION\_ID; Secure; HttpOnly

```



<div style="text-align: center;">

  <img src="/top10-owasp-blog/assets/images/brw3.png" alt=" take the session " style="width: 40%; border: 1px solid #ccc; border-radius: 8px;">

  <p><em>Figure 3: </em>  </p>

</div>




==> This session value belongs to carlos.





\### Step 5 — Replace the session in the browser



-Open the lab in your browser.



-Press F12 → go to Application (or Storage) → Cookies.



\-Replace your current session cookie with the stolen value from Step 4.





<div style="text-align: center;">

  <img src="/top10-owasp-blog/assets/images/brw4.png" alt=" " style="width: 40%; border: 1px solid #ccc; border-radius: 8px;">

  <p><em>Figure 4: </em>  </p>

</div>





\-Refresh the page — you will now be authenticated as carlos.



==> The lab is solved.



\## Mitigation

To prevent this vulnerability:



1.Enforce strict rate-limiting and account lockout per username, not just per request.



2.Validate and sanitize request formats — reject multiple credentials in a single request.



3\.Implement MFA (multi-factor authentication) to make brute-force ineffective.



4\.Monitor unusual login patterns (e.g., large JSON arrays in authentication requests).





\### Conclusion



This lab demonstrates how allowing multiple credentials in a single login request can render brute-force protections useless. By sending a password list as an array, an attacker can bypass per-request rate limits, obtain a valid session token, and hijack the victim’s account. Proper input validation and strong authentication controls are essential to prevent such attacks.













