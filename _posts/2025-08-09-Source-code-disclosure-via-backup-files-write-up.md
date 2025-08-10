---

title: "Lab: Source code disclosure via backup files"

date: 2025-08-09

layout: post

tags: \[security-misconfiguration, backup-files, web-security, portswigger]

---



\### Lab Description



This lab contains a Security Misconfiguration vulnerability. The application exposes backup files containing source code and configuration files due to improper server configuration.



An attacker can download these backup files and retrieve sensitive information such as database credentials or secret keys from the source code.



Your task is to locate and download the backup file, analyze its contents to find the secret password, then submit the secret password to complete the lab.



---



\## Analysis and Exploitation



\### Checking `robots.txt`

`robots.txt` is a file placed at the root of a website that tells web crawlers (like Google) which parts of the site to avoid indexing. It is \*\*not a security control\*\*, but rather a guideline for search engines.



In this lab, inspecting `/robots.txt` revealed:

This indicates the backup file exists and should not be crawled, but it does \*\*not prevent direct access\*\*. Attackers can use this information to locate sensitive files.



---



\### 1. Discovering the exposed backup file



By exploring the application directories and testing common backup filenames, we attempt to access typical backup file URLs such as:



```

\- `/backup.zip`

\- `/backup.tar.gz`

\- `/backup.bak`

\- `/site\_backup.zip`

```



Using Burp Suite or a browser, requesting `/backup.zip` returns a valid file download instead of a 404 or access denied response.



<div style="text-align: center;">

&nbsp; <img src="/top10-owasp-blog/assets/images/s1.png" alt="Backup file download" style="width: 40%; border: 1px solid #ccc; border-radius: 8px;">

&nbsp; <p><em>Figure 1: </em> Downloading exposed backup.zip file</p>

</div>



---



\### 2. Download and extract the backup file



The downloaded file is a zip archive. Extracting it locally reveals the project source code including PHP files such as:



```

\- `config.php`

\- `db\_connect.php`

\- Other application source files

```

<div style="text-align: center;">

  <img src="/top10-owasp-blog/assets/images/sf2.png" alt="Backup file download" style="width: 40%; border: 1px solid #ccc; border-radius: 8px;">

  <p><em>Figure 2: </em> Downloading exposed backup.zip file</p>

</div>





---



\### 3. Analyze source code for sensitive information



Opening `config.php` reveals database credentials:



```php

<?php

$db\_host = 'localhost';

$db\_user = 'admin';

$db\_password = 'SuperSecretPass123';

$db\_name = 'appdb';

?>



<div style="text-align: center;">

  <img src="/top10-owasp-blog/assets/images/sf3.png" alt="Analyze source code" style="width: 40%; border: 1px solid #ccc; border-radius: 8px;">

  <p><em>Figure 3: </em> Analyze source code</p>

</div>



\### 4. Submit the secret to complete the lab

Returning to the lab interface, enter the extracted secret password into the secret submission form.



<div style="text-align: center;">

<img src="/top10-owasp-blog/assets/images/sf4.png" alt="" style="width: 40%; border: 1px solid #ccc; border-radius: 8px;">

<p><em>Figure 4: </em>  file</p>

</div>



\### Conclusion



This lab demonstrates how a simple security misconfiguration, exposing backup files containing source code, can lead to serious information disclosure vulnerabilities.



By accessing and analyzing the backup archive, we retrieved sensitive database credentials and solved the lab.



Proper configuration and file management are essential to avoid such leaks and protect sensitive information from attackers.

