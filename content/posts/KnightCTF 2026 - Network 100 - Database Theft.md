+++
date = 2026-01-21
description ="KnightCTF 2026 - Network 100 - Database Theft"
title = "KnightCTF 2026 - Network 100 - Database Theft"
[taxonomies]
tags = ["ctf", "networking", "wireshark", "tshark"]
+++
## Task

```
## Database Credentials Theft

### 100 Points

Author

The attacker's ultimate goal was to access our database. During the post-exploitation phase, they managed to extract database credentials from the compromised system. Find the database username and password that were exposed.

> Use pcap3.pcapng file to solve this challenge.

**Flag Format: KCTF{username_password}**

_**Author: TareqAhamed (0xt4req)**_
```

## Tshark Dump

This was the easiest one so far.
Since we know from previous task that reverse shell was running on 9576, lets only dump tcp stream from it, and convert it from hex to bin/ascii.
That way we can basically see what the attacker was running in reverse shell:
```bash
tshark -r pcap3.pcapng -Y "tcp.port==9576" -T fields -e tcp.payload | xxd -r -p

```

Output:
```bash
www-data@ubuntu-server-2:/var/www/html/wordpress/wp-admin$ cd ..
cd ..
www-data@ubuntu-server-2:/var/www/html/wordpress$ ls
ls
index.php
license.txt
readme.html
wp-activate.php
wp-admin
wp-blog-header.php
wp-comments-post.php
wp-config-sample.php
wp-config.php
wp-content
wp-cron.php
wp-includes
wp-links-opml.php
wp-load.php
wp-login.php
wp-mail.php
wp-settings.php
wp-signup.php
wp-trackback.php
xmlrpc.php
.............
www-data@ubuntu-server-2:/var/www/html/wordpress$ cat wp-config.php
cat wp-config.php
<?php
/**
 * The base configuration for WordPress
 *
 * The wp-config.php creation script uses this file during the installation.
 * You don't have to use the website, you can copy this file to "wp-config.php"
 * and fill in the values.
 *
 * This file contains the following configurations:
 *
 * * Database settings
 * * Secret keys
 * * Database table prefix
 * * ABSPATH
 *
 * @link https://developer.wordpress.org/advanced-administration/wordpress/wp-config/
 *
 * @package WordPress
 */

// ** Database settings - You can get this info from your web host ** //
/** The name of the database for WordPress */
define( 'DB_NAME', 'wordpress_db' );

/** Database username */
define( 'DB_USER', 'wpuser' );

/** Database password */
define( 'DB_PASSWORD', 'wp@user123' );

/** Database hostname */
define( 'DB_HOST', 'localhost' );

/** Database charset to use in creating database tables. */
define( 'DB_CHARSET', 'utf8mb4' );

/** The database collate type. Don't change this if in doubt. */
define( 'DB_COLLATE', '' );

....................
```

And, well, yes thats a password and username right there.

## Flag

Flag is: **KCTF{wpuser_wp@user123}**

![](/images/7a483ecec97a116e2f38fc8f665e5570.png)
