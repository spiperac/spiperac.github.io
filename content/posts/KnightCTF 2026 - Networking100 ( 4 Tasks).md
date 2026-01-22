+++
date = 2026-01-21
description ="KnightCTF 2026 - Networking100"
title = "KnightCTF 2026 - Networking100"
[taxonomies]
tags = ["ctf", "networking", "wireshark", "tshark"]
+++

## Task 1 - Exploitation

```
The attacker appears to have identified a web application running on our server. 
We need to determine what application was being targeted. 
Find the version and username associated with the application in the capture.

Flag Format: KCTF{version_username}
```

Download: [pcap2.pcapng](https://drive.google.com/file/d/1r5Huq9jVrcNGMP-eX2qMgaHoD6bQpV6U/view?usp=sharing)
### pcap2.pcapng - Finding Username

Let’s analyze the pcap file with Wireshark by first looking for a username.  
We want to check POST methods in login forms by filtering:
```
http.request.method==POST && http.request.uri contains "login.php"
```

![](/images/d13fb4465bab28210dd6afff732179a5.png)

Right from the start we can see that the web application in question is WordPress, not only from this filter but also because, when we inspect the traffic, we see many WPScan requests.

Since there are only two POST requests, it is easy to find the username.  
If we inspect the first request’s HTML form data, we see:

```
HTML Form URL Encoded: application/x-www-form-urlencoded
    Form item: "log" = "kadmin_user"
    Form item: "pwd" = "f750d046"

```

![](/images/60c29f3547f2c82ff48d57daefa8a52a.png)

So the username is: **kadmin_user**

**Note:**  
The second request also contains a user, but in the form of an email address:
```
HTML Form URL Encoded: application/x-www-form-urlencoded
    Form item: "log" = "tushar@gmail.com"
        Key: log
        Value: tushar@gmail.com
    Form item: "pwd" = "1234566"
        Key: pwd
        Value: 1234566
    Form item: "rememberme" = "forever"
        Key: rememberme
        Value: forever
    Form item: "wp-submit" = "Log In"
        Key: wp-submit
        Value: Log In
    Form item: "redirect_to" = "http://192.168.1.102/wordpress/"
        Key: redirect_to
        Value: http://192.168.1.102/wordpress/
    Form item: "testcookie" = "1"
        Key: testcookie
        Value: 1
```

This could be a fallback if the first attempt failed, but it looks like a brute-force attempt, since the cookie is strange and the password is `1234566`.
### pcap2.pcapng - Finding WordPress version

My approach here was, I basically dumped all HTML objects from the pcap file:
```
~/Vault/isec/ctf/knight2k26/net100-exploitation  ✓ $ tshark -r pcap2.pcapng --export-objects http,./dump

```

Then I ran a few `grep` commands, which quickly yielded a result:

```
~/Vault/isec/ctf/knight2k26/net100-exploitation  ✓ $ grep -R "generator" dump/wordpress*

dump/wordpress:<meta name="generator" content="WordPress 6.9" />
dump/wordpress(1):<meta name="generator" content="WordPress 6.9" />
dump/wordpress(6):<meta name="generator" content="WordPress 6.9" />
dump/wordpress(7):<meta name="generator" content="WordPress 6.9" />
dump/wordpress(8):<meta name="generator" content="WordPress 6.9" />

```

So the WordPress version is: **6.9**

#### Alternative method

Another way to find this is by dumping all TCP streams, iterating through them, and grepping for the string `"WordPress"`:
```shell-session
~/Vault/isec/ctf/knight2k26/net100-exploitation  ✗1 $ for i in $(tshark -r pcap2.pcapng -T fields -e tcp.stream | sort -n | uniq); do
  tshark -r pcap2.pcapng -q -z follow,tcp,ascii,$i;
done | grep -a "WordPress"

X-Redirect-By: WordPress
X-Redirect-By: WordPress
X-Redirect-By: WordPress
X-Redirect-By: WordPress
X-Redirect-By: WordPress
X-Redirect-By: WordPress
X-Redirect-By: WordPress
X-Redirect-By: WordPress
X-Redirect-By: WordPress
X-Redirect-By: WordPress
X-Redirect-By: WordPress
X-Redirect-By: WordPress
X-Redirect-By: WordPress
.<generator uri="https://wordpress.org/" version="6.9">WordPress</generator>
 type="html"><![CDATA[Welcome to WordPress. This is your first post. Edit or delete it, then start writing!]]></summary>
<p>Welcome to WordPress. This is your first post. Edit or delete it, then start writing!</p>
."description": "Displays a link to edit the comment in the WordPress Dashboard. This link is only visible to users with the edit comment capability.",
## WordPress Modification - We prepend some unexpired 'legacy' 1024bit certificates
X-Redirect-By: WordPress
X-Redirect-By: WordPress
X-Redirect-By: WordPress
X-Redirect-By: WordPress

```

This also reveals:
```html
<generator uri="https://wordpress.org/" version="6.9">WordPress</generator>
 type="html"><![CDATA[Welcome to WordPress. This is your first post. Edit or delete it, then start writing!]]></summary>
```

### Flag

Flag is: **KCTF{6.9_kadmin_user}**

![](/images/766d3fd32e5eac23a6cbb9f9d7ec5792.png)


## Task 2 - Vulnerability Exploitation

```
Our web application was compromised through a vulnerable plugin. 
The attacker exploited a known vulnerability to gain initial access.
Identify the vulnerable plugin and its version that was exploited.

> Use pcap2.pcapng to solve this challenge.

**Flag Format KCTF{plugin_name_version}**
```



### pcap2.pcapng - WP Plugin Analysis

Since we already know from the previous task that the target is WordPress, and we are looking for a vulnerable plugin, I dumped all requests containing `"wp-content/plugins"`.

The goal here is simply to identify which plugin was actually probed and exploited, rather than listing every possible path.

```shell-session
~/Vault/isec/ctf/knight2k26/net100-exploitation  ✓ $ tshark -r pcap2.pcapng -Y 'frame contains "wp-content/plugins"' -T fields -e frame.time -e ip.src -e http.request.uri

2026-01-19T17:37:53.390368000+0100	192.168.1.104	/wordpress/wp-content/plugins
2026-01-19T17:37:53.390880000+0100	192.168.1.102	/wordpress/wp-content/plugins
2026-01-19T17:40:46.967469000+0100	192.168.1.104	/wordpress/wp-content/plugins/social-warfare/readme.txt
2026-01-19T17:40:46.974850000+0100	192.168.1.104	/wordpress/wp-content/plugins/social-warfare/readme.txt
2026-01-19T17:40:46.984270000+0100	192.168.1.104	/wordpress/wp-content/plugins/thim-blocks/readme.txt
2026-01-19T17:40:46.990432000+0100	192.168.1.104	/wordpress/wp-content/plugins/thim-blocks/readme.txt
2026-01-19T17:40:50.251135000+0100	192.168.1.104	/wordpress/wp-content/themes/TheStyle/wp-content/plugins/timthumb.php
2026-01-19T17:40:50.467320000+0100	192.168.1.104	/wordpress/wp-content/plugins/add-new-default-avatar-emrikols-fork/includes/thumb.php
2026-01-19T17:40:50.467956000+0100	192.168.1.104	/wordpress/wp-content/plugins/add-new-default-avatar-emrikols-fork/includes/timthumb.php
2026-01-19T17:40:50.470145000+0100	192.168.1.104	/wordpress/wp-content/plugins/a-gallery/thumb.php
2026-01-19T17:40:50.471617000+0100	192.168.1.104	/wordpress/wp-content/plugins/a-gallery/timthumb.php
2026-01-19T17:40:50.472238000+0100	192.168.1.104	/wordpress/wp-content/plugins/auto-attachments/thumb.php
2026-01-19T17:40:50.475310000+0100	192.168.1.104	/wordpress/wp-content/plugins/auto-attachments/thumb.phpthumb.php
2026-01-19T17:40:50.475948000+0100	192.168.1.104	/wordpress/wp-content/plugins/auto-attachments/thumb.phptimthumb.php
2026-01-19T17:40:50.477189000+0100	192.168.1.104	/wordpress/wp-content/plugins/cac-featured-content/timthumb.php
2026-01-19T17:40:50.477818000+0100	192.168.1.104	/wordpress/wp-content/plugins/category-grid-view-gallery/includes/thumb.php
2026-01-19T17:40:50.477818000+0100	192.168.1.104	/wordpress/wp-content/plugins/category-grid-view-gallery/includes/timthumb.php
2026-01-19T17:40:50.479677000+0100	192.168.1.104	/wordpress/wp-content/plugins/category-grid-view-gallery/timthumb.php
2026-01-19T17:40:50.480316000+0100	192.168.1.104	/wordpress/wp-content/plugins/category-list-portfolio-page/scripts/timthumb.php
2026-01-19T17:40:50.480952000+0100	192.168.1.104	/wordpress/wp-content/plugins/cms-pack/timthumb.php
2026-01-19T17:40:50.482188000+0100	192.168.1.104	/wordpress/wp-content/plugins/communitypress/cp-themes/cp-default/timthumb.php
2026-01-19T17:40:50.483538000+0100	192.168.1.104	/wordpress/wp-content/plugins/communitypress/cp-wp-content/themes/cp-default/timthumb.php
2026-01-19T17:40:50.485121000+0100	192.168.1.104	/wordpress/wp-content/plugins/db-toolkit/libs/thumb.php
2026-01-19T17:40:50.487843000+0100	192.168.1.104	/wordpress/wp-content/plugins/dp-thumbnail/timthumb/thumb.php
2026-01-19T17:40:50.488476000+0100	192.168.1.104	/wordpress/wp-content/plugins/db-toolkit/libs/timthumb.php
2026-01-19T17:40:50.488476000+0100	192.168.1.104	/wordpress/wp-content/plugins/dp-thumbnail/timthumb/timthumb.php
2026-01-19T17:40:50.491115000+0100	192.168.1.104	/wordpress/wp-content/plugins/dp-thumbnail/timthumb/timthumb.phpthumb.php
2026-01-19T17:40:50.491141000+0100	192.168.1.104	/wordpress/wp-content/plugins/dp-thumbnail/timthumb/timthumb.phptimthumb.php
2026-01-19T17:40:50.491781000+0100	192.168.1.104	/wordpress/wp-content/plugins/dukapress/lib/thumb.php
2026-01-19T17:40:50.492424000+0100	192.168.1.104	/wordpress/wp-content/plugins/dukapress/lib/timthumb.php
2026-01-19T17:40:50.493063000+0100	192.168.1.104	/wordpress/wp-content/plugins/dukapress/lib/timthumb.phpthumb.php
2026-01-19T17:40:50.496749000+0100	192.168.1.104	/wordpress/wp-content/plugins/dukapress/timthumb.php
2026-01-19T17:40:50.496785000+0100	192.168.1.104	/wordpress/wp-content/plugins/dukapress/lib/timthumb.phptimthumb.php
2026-01-19T17:40:50.497402000+0100	192.168.1.104	/wordpress/wp-content/plugins/ecobiz/timthumb.php
2026-01-19T17:40:50.499551000+0100	192.168.1.104	/wordpress/wp-content/plugins/event-espresso-free/includes/functions/timthumb.php
2026-01-19T17:40:50.500177000+0100	192.168.1.104	/wordpress/wp-content/plugins/ePhoto/timthumb.php
2026-01-19T17:40:50.500832000+0100	192.168.1.104	/wordpress/wp-content/plugins/events-manager/includes/thumbnails/timthumb.php
2026-01-19T17:40:50.501458000+0100	192.168.1.104	/wordpress/wp-content/plugins/extend-wordpress/helpers/timthumb/image.php
2026-01-19T17:40:50.502085000+0100	192.168.1.104	/wordpress/wp-content/plugins/featured-post-with-thumbnail/scripts/timthumb.php
2026-01-19T17:40:50.502709000+0100	192.168.1.104	/wordpress/wp-content/plugins/feature-slideshow/timthumb.php
2026-01-19T17:40:50.503326000+0100	192.168.1.104	/wordpress/wp-content/plugins/fotoslide/timthumb.php
2026-01-19T17:40:50.504565000+0100	192.168.1.104	/wordpress/wp-content/plugins/front-slider/scripts/timthumb.php
2026-01-19T17:40:50.505914000+0100	192.168.1.104	/wordpress/wp-content/plugins/geotag/tools/timthumb/timthumb.phptimthumb.php
2026-01-19T17:40:50.506546000+0100	192.168.1.104	/wordpress/wp-content/plugins/geotag/tools/timthumb/timthumb.php
2026-01-19T17:40:50.508705000+0100	192.168.1.104	/wordpress/wp-content/plugins/hungred-image-fit/scripts/timthumb.php
2026-01-19T17:40:50.508707000+0100	192.168.1.104	/wordpress/wp-content/plugins/highlighter/libs/timthumb.php
2026-01-19T17:40:50.511118000+0100	192.168.1.104	/wordpress/wp-content/plugins/igit-related-posts-with-thumb-images-after-posts/thumb.php
2026-01-19T17:40:50.511118000+0100	192.168.1.104	/wordpress/wp-content/plugins/igit-posts-slider-widget/timthumb.php
2026-01-19T17:40:50.511118000+0100	192.168.1.104	/wordpress/wp-content/plugins/igit-related-posts-widget/timthumb.php
2026-01-19T17:40:50.515031000+0100	192.168.1.104	/wordpress/wp-content/plugins/igit-related-posts-with-thumb-images-after-posts/timthumb.php
2026-01-19T17:40:50.515655000+0100	192.168.1.104	/wordpress/wp-content/plugins/image-symlinks/custom/thumb.php
2026-01-19T17:40:50.515656000+0100	192.168.1.104	/wordpress/wp-content/plugins/image-rotator-widget/timthumb.php
2026-01-19T17:40:50.516280000+0100	192.168.1.104	/wordpress/wp-content/plugins/image-symlinks/custom/timthumb.php
2026-01-19T17:40:50.516286000+0100	192.168.1.104	/wordpress/wp-content/plugins/image-symlinks/framework/includes/thumb.php
2026-01-19T17:40:50.519871000+0100	192.168.1.104	/wordpress/wp-content/plugins/image-symlinks/framework/includes/timthumb.php
2026-01-19T17:40:50.521208000+0100	192.168.1.104	/wordpress/wp-content/plugins/image-symlinks/framework/thumb/thumb.php
2026-01-19T17:40:50.521208000+0100	192.168.1.104	/wordpress/wp-content/plugins/image-symlinks/functions/scripts/thumb.php
2026-01-19T17:40:50.521208000+0100	192.168.1.104	/wordpress/wp-content/plugins/image-symlinks/framework/thumb/timthumb.php
2026-01-19T17:40:50.521837000+0100	192.168.1.104	/wordpress/wp-content/plugins/image-symlinks/functions/scripts/timthumb.php
2026-01-19T17:40:50.523076000+0100	192.168.1.104	/wordpress/wp-content/plugins/image-symlinks/functions/thumb.php
2026-01-19T17:40:50.525902000+0100	192.168.1.104	/wordpress/wp-content/plugins/image-symlinks/functions/thumb/thumb.php
2026-01-19T17:40:50.528024000+0100	192.168.1.104	/wordpress/wp-content/plugins/image-symlinks/functions/timthumb.php
2026-01-19T17:40:50.528643000+0100	192.168.1.104	/wordpress/wp-content/plugins/image-symlinks/images/thumb.php
2026-01-19T17:40:50.528644000+0100	192.168.1.104	/wordpress/wp-content/plugins/image-symlinks/functions/timthumb/timthumb.php
2026-01-19T17:40:50.528644000+0100	192.168.1.104	/wordpress/wp-content/plugins/image-symlinks/images/timthumb.php
2026-01-19T17:40:50.529885000+0100	192.168.1.104	/wordpress/wp-content/plugins/image-symlinks/includes/thumb.php
2026-01-19T17:40:50.531114000+0100	192.168.1.104	/wordpress/wp-content/plugins/image-symlinks/includes/thumb/thumb.php
2026-01-19T17:40:50.532347000+0100	192.168.1.104	/wordpress/wp-content/plugins/image-symlinks/includes/thumb/timthumb.php
2026-01-19T17:40:50.532351000+0100	192.168.1.104	/wordpress/wp-content/plugins/image-symlinks/includes/timthumb.php
2026-01-19T17:40:50.534192000+0100	192.168.1.104	/wordpress/wp-content/plugins/image-symlinks/includes/timthumb/timthumb.php
2026-01-19T17:40:50.534192000+0100	192.168.1.104	/wordpress/wp-content/plugins/image-symlinks/inc/thumb.php
2026-01-19T17:40:50.534811000+0100	192.168.1.104	/wordpress/wp-content/plugins/image-symlinks/inc/timthumb.php
2026-01-19T17:40:50.537895000+0100	192.168.1.104	/wordpress/wp-content/plugins/image-symlinks/js/thumb.php
2026-01-19T17:40:50.541149000+0100	192.168.1.104	/wordpress/wp-content/plugins/image-symlinks/js/timthumb.php
2026-01-19T17:40:50.541174000+0100	192.168.1.104	/wordpress/wp-content/plugins/image-symlinks/layouts/thumb.php
2026-01-19T17:40:50.541794000+0100	192.168.1.104	/wordpress/wp-content/plugins/image-symlinks/layouts/timthumb.php
2026-01-19T17:40:50.541799000+0100	192.168.1.104	/wordpress/wp-content/plugins/image-symlinks/lib/custom/thumb.php
2026-01-19T17:40:50.542420000+0100	192.168.1.104	/wordpress/wp-content/plugins/image-symlinks/lib/custom/timthumb.php
2026-01-19T17:40:50.545819000+0100	192.168.1.104	/wordpress/wp-content/plugins/image-symlinks/library/functions/thumb.php
2026-01-19T17:40:50.548452000+0100	192.168.1.104	/wordpress/wp-content/plugins/image-symlinks/library/resource/thumb.php
2026-01-19T17:40:50.549082000+0100	192.168.1.104	/wordpress/wp-content/plugins/image-symlinks/library/thumb.php
2026-01-19T17:40:50.549083000+0100	192.168.1.104	/wordpress/wp-content/plugins/image-symlinks/library/resource/timthumb.php
2026-01-19T17:40:50.549083000+0100	192.168.1.104	/wordpress/wp-content/plugins/image-symlinks/library/functions/timthumb.php
2026-01-19T17:40:50.549707000+0100	192.168.1.104	/wordpress/wp-content/plugins/image-symlinks/library/thumb/thumb.php
2026-01-19T17:40:50.552357000+0100	192.168.1.104	/wordpress/wp-content/plugins/image-symlinks/library/thumb/timthumb.php
2026-01-19T17:40:50.554714000+0100	192.168.1.104	/wordpress/wp-content/plugins/image-symlinks/library/timthumb.php
2026-01-19T17:40:50.555339000+0100	192.168.1.104	/wordpress/wp-content/plugins/image-symlinks/lib/script/thumb.php
2026-01-19T17:40:50.555339000+0100	192.168.1.104	/wordpress/wp-content/plugins/image-symlinks/library/timthumb/timthumb.php
2026-01-19T17:40:50.555340000+0100	192.168.1.104	/wordpress/wp-content/plugins/image-symlinks/lib/script/timthumb.php
2026-01-19T17:40:50.555968000+0100	192.168.1.104	/wordpress/wp-content/plugins/image-symlinks/lib/thumb.php
2026-01-19T17:40:50.558033000+0100	192.168.1.104	/wordpress/wp-content/plugins/image-symlinks/lib/thumb/thumb.php
2026-01-19T17:40:50.560428000+0100	192.168.1.104	/wordpress/wp-content/plugins/image-symlinks/lib/timthumb.php
2026-01-19T17:40:50.561054000+0100	192.168.1.104	/wordpress/wp-content/plugins/image-symlinks/lib/thumb/timthumb.php
2026-01-19T17:40:50.562889000+0100	192.168.1.104	/wordpress/wp-content/plugins/image-symlinks/lib/timthumb/timthumb.php
2026-01-19T17:40:50.563512000+0100	192.168.1.104	/wordpress/wp-content/plugins/image-symlinks/modules/thumb.php
2026-01-19T17:40:50.563512000+0100	192.168.1.104	/wordpress/wp-content/plugins/image-symlinks/modules/timthumb.php
2026-01-19T17:40:50.565376000+0100	192.168.1.104	/wordpress/wp-content/plugins/image-symlinks/options/timthumb.php
2026-01-19T17:40:50.565377000+0100	192.168.1.104	/wordpress/wp-content/plugins/image-symlinks/options/thumb.php
2026-01-19T17:40:50.565376000+0100	192.168.1.104	/wordpress/wp-content/plugins/image-symlinks/scripts/thumb.php
2026-01-19T17:40:50.566614000+0100	192.168.1.104	/wordpress/wp-content/plugins/image-symlinks/scripts/thumb/thumb.php
2026-01-19T17:40:50.568858000+0100	192.168.1.104	/wordpress/wp-content/plugins/image-symlinks/scripts/thumb/timthumb.php
2026-01-19T17:40:50.569488000+0100	192.168.1.104	/wordpress/wp-content/plugins/image-symlinks/scripts/timthumb.php
2026-01-19T17:40:50.571313000+0100	192.168.1.104	/wordpress/wp-content/plugins/image-symlinks/scripts/timthumb/timthumb.php
2026-01-19T17:40:50.571942000+0100	192.168.1.104	/wordpress/wp-content/plugins/image-symlinks/thumb/thumb.php
2026-01-19T17:40:50.571942000+0100	192.168.1.104	/wordpress/wp-content/plugins/image-symlinks//thumb.php
2026-01-19T17:40:50.573181000+0100	192.168.1.104	/wordpress/wp-content/plugins/image-symlinks/thumb/timthumb.php
2026-01-19T17:40:50.573934000+0100	192.168.1.104	/wordpress/wp-content/plugins/image-symlinks//timthumb.php
2026-01-19T17:40:50.578049000+0100	192.168.1.104	/wordpress/wp-content/plugins/image-symlinks/timthumb.php
2026-01-19T17:40:50.578683000+0100	192.168.1.104	/wordpress/wp-content/plugins/image-symlinks/tools/thumb/thumb.php
2026-01-19T17:40:50.578683000+0100	192.168.1.104	/wordpress/wp-content/plugins/image-symlinks/tools/thumb.php
2026-01-19T17:40:50.578683000+0100	192.168.1.104	/wordpress/wp-content/plugins/image-symlinks/timthumb/timthumb.php
2026-01-19T17:40:50.588083000+0100	192.168.1.104	/wordpress/wp-content/plugins/image-symlinks/tools/thumb/timthumb.php
2026-01-19T17:40:50.588717000+0100	192.168.1.104	/wordpress/wp-content/plugins/image-symlinks/tools/timthumb/timthumb.php
2026-01-19T17:40:50.588719000+0100	192.168.1.104	/wordpress/wp-content/plugins/islidex/js/thumb.php
2026-01-19T17:40:50.588718000+0100	192.168.1.104	/wordpress/wp-content/plugins/islidex/includes/timthumb/timthumb.php
2026-01-19T17:40:50.588718000+0100	192.168.1.104	/wordpress/wp-content/plugins/image-symlinks/tools/timthumb.php
2026-01-19T17:40:50.594033000+0100	192.168.1.104	/wordpress/wp-content/plugins/islidex/js/timthumb.php
2026-01-19T17:40:50.594667000+0100	192.168.1.104	/wordpress/wp-content/plugins/islidex/js/timthumb.phpthumb.php
2026-01-19T17:40:50.595906000+0100	192.168.1.104	/wordpress/wp-content/plugins/islidex/js/timthumb.phptimthumb.php
2026-01-19T17:40:50.595906000+0100	192.168.1.104	/wordpress/wp-content/plugins/jquery-slider-for-featured-content/scripts/timthumb.php
2026-01-19T17:40:50.595906000+0100	192.168.1.104	/wordpress/wp-content/plugins/js-multihotel/includes/timthumb.php
2026-01-19T17:40:50.598410000+0100	192.168.1.104	/wordpress/wp-content/plugins/kc-related-posts-by-category/timthumb.php
2026-01-19T17:40:50.602097000+0100	192.168.1.104	/wordpress/wp-content/plugins/lisl-last-image-slider/timthumb.php
2026-01-19T17:40:50.602124000+0100	192.168.1.104	/wordpress/wp-content/plugins/logo-management/includes/timthumb.php
2026-01-19T17:40:50.602751000+0100	192.168.1.104	/wordpress/wp-content/plugins/mangapress/includes/mangapress-timthumb.php
2026-01-19T17:40:50.602750000+0100	192.168.1.104	/wordpress/wp-content/plugins/kino-gallery/timthumb.php
2026-01-19T17:40:50.603376000+0100	192.168.1.104	/wordpress/wp-content/plugins/mediarss-external-gallery/timthumb.php
2026-01-19T17:40:50.605344000+0100	192.168.1.104	/wordpress/wp-content/plugins/meenews-newsletter/inc/classes/timthumb.php
2026-01-19T17:40:50.606839000+0100	192.168.1.104	/wordpress/wp-content/plugins/mobileposty-mobile-site-generator/timthumb.php
2026-01-19T17:40:50.608791000+0100	192.168.1.104	/wordpress/wp-content/plugins/pictmobi-widget/timthumb.php
2026-01-19T17:40:50.608823000+0100	192.168.1.104	/wordpress/wp-content/plugins/mobile-smart/includes/timthumb.php
2026-01-19T17:40:50.609462000+0100	192.168.1.104	/wordpress/wp-content/plugins/pointelle-slider/includes/timthumb.php
2026-01-19T17:40:50.611390000+0100	192.168.1.104	/wordpress/wp-content/plugins/premium-list-magnet/inc/thumb.php
2026-01-19T17:40:50.611390000+0100	192.168.1.104	/wordpress/wp-content/plugins/premium-list-magnet/inc/timthumb.php
2026-01-19T17:40:50.613964000+0100	192.168.1.104	/wordpress/wp-content/plugins/really-easy-slider/inc/thumb.php
2026-01-19T17:40:50.616390000+0100	192.168.1.104	/wordpress/wp-content/plugins/rent-a-car/libs/timthumb.php
2026-01-19T17:40:50.616458000+0100	192.168.1.104	/wordpress/wp-content/plugins/seo-image-galleries/timthumb.php
2026-01-19T17:40:50.617083000+0100	192.168.1.104	/wordpress/wp-content/plugins/sharepulse/timthumb.php
2026-01-19T17:40:50.619344000+0100	192.168.1.104	/wordpress/wp-content/plugins/shortcodes-ultimate/lib/timthumb.php
2026-01-19T17:40:50.619970000+0100	192.168.1.104	/wordpress/wp-content/plugins/simple-coverflow/timthumb.php
2026-01-19T17:40:50.619970000+0100	192.168.1.104	/wordpress/wp-content/plugins/sh-slideshow/timthumb.php
2026-01-19T17:40:50.621827000+0100	192.168.1.104	/wordpress/wp-content/plugins/simple-post-thumbnails/timthumb.php
2026-01-19T17:40:50.623066000+0100	192.168.1.104	/wordpress/wp-content/plugins/sliceshow-slideshow/scripts/timthumb.php
2026-01-19T17:40:50.624550000+0100	192.168.1.104	/wordpress/wp-content/plugins/smart-related-posts-thumbnails/timthumb.php
2026-01-19T17:40:50.624550000+0100	192.168.1.104	/wordpress/wp-content/plugins/simple-slide-show/timthumb.php
2026-01-19T17:40:50.624550000+0100	192.168.1.104	/wordpress/wp-content/plugins/slider-pro/includes/timthumb/timthumb.php
2026-01-19T17:40:50.625838000+0100	192.168.1.104	/wordpress/wp-content/plugins/tag-gallery/timthumb/timthumb.php
2026-01-19T17:40:50.626482000+0100	192.168.1.104	/wordpress/wp-content/plugins/thethe-image-slider/timthumb.php
2026-01-19T17:40:50.630133000+0100	192.168.1.104	/wordpress/wp-content/plugins/timthumb-meets-tinymce/ttplugin/timthumb.php
2026-01-19T17:40:50.630752000+0100	192.168.1.104	/wordpress/wp-content/plugins/thumbnails-anywhere/timthumb.php
2026-01-19T17:40:50.633189000+0100	192.168.1.104	/wordpress/wp-content/plugins/todo-espaco-online-links-felipe/timthumb.php
2026-01-19T17:40:50.633219000+0100	192.168.1.104	/wordpress/wp-content/plugins/tim-widget/scripts/timthumb.php
2026-01-19T17:40:50.633834000+0100	192.168.1.104	/wordpress/wp-content/plugins/timthumb-vulnerability-scanner/cg-tvs-admin-panel.php
2026-01-19T17:40:50.635065000+0100	192.168.1.104	/wordpress/wp-content/plugins/uBillboard/cache/timthumb.php
2026-01-19T17:40:50.635065000+0100	192.168.1.104	/wordpress/wp-content/plugins/uBillboard/lib/timthumb.php
2026-01-19T17:40:50.637272000+0100	192.168.1.104	/wordpress/wp-content/plugins/uBillboard/thumb.php
2026-01-19T17:40:50.637897000+0100	192.168.1.104	/wordpress/wp-content/plugins/uBillboard/timthumb.php
2026-01-19T17:40:50.637899000+0100	192.168.1.104	/wordpress/wp-content/plugins/uBillboard/timthumb.phpthumb.php
2026-01-19T17:40:50.639746000+0100	192.168.1.104	/wordpress/wp-content/plugins/ultimate-posts-widget/thumb.php
2026-01-19T17:40:50.639746000+0100	192.168.1.104	/wordpress/wp-content/plugins/uBillboard/timthumb.phptimthumb.php
2026-01-19T17:40:50.640377000+0100	192.168.1.104	/wordpress/wp-content/plugins/verve-meta-boxes/tools/timthumb.php
2026-01-19T17:40:50.641625000+0100	192.168.1.104	/wordpress/wp-content/plugins/vk-gallery/lib/thumb.php
2026-01-19T17:40:50.641625000+0100	192.168.1.104	/wordpress/wp-content/plugins/vk-gallery/lib/timthumb.php
2026-01-19T17:40:50.644264000+0100	192.168.1.104	/wordpress/wp-content/plugins/vslider/thumb.php
2026-01-19T17:40:50.645122000+0100	192.168.1.104	/wordpress/wp-content/plugins/vslider/timthumb.php
2026-01-19T17:40:50.645751000+0100	192.168.1.104	/wordpress/wp-content/plugins/woo-tumblog/functions/thumb.php
2026-01-19T17:40:50.646980000+0100	192.168.1.104	/wordpress/wp-content/plugins/woo-tumblog/thumb.php
2026-01-19T17:40:50.646980000+0100	192.168.1.104	/wordpress/wp-content/plugins/woo-tumblog/functions/timthumb.php
2026-01-19T17:40:50.647609000+0100	192.168.1.104	/wordpress/wp-content/plugins/wordpress-gallery-plugin/timthumb.php
2026-01-19T17:40:50.649743000+0100	192.168.1.104	/wordpress/wp-content/plugins/wordpress-popular-posts/scripts/timthumb.php
2026-01-19T17:40:50.650366000+0100	192.168.1.104	/wordpress/wp-content/plugins/wordpress-news-ticker-plugin/timthumb.php
2026-01-19T17:40:50.651657000+0100	192.168.1.104	/wordpress/wp-content/plugins/wordpress-thumbnail-slider/timthumb.php
2026-01-19T17:40:50.652286000+0100	192.168.1.104	/wordpress/wp-content/plugins/wp-featured-post-with-thumbnail/scripts/timthumb.php
2026-01-19T17:40:50.652288000+0100	192.168.1.104	/wordpress/wp-content/plugins/wp-dailybooth/timthumb.php
2026-01-19T17:40:50.654138000+0100	192.168.1.104	/wordpress/wp-content/plugins/wp-marketplace/libs/thumb.php
2026-01-19T17:40:50.654763000+0100	192.168.1.104	/wordpress/wp-content/plugins/wp-marketplace/libs/timthumb.php
2026-01-19T17:40:50.655383000+0100	192.168.1.104	/wordpress/wp-content/plugins/wp-marketplace/libs/timthumb.phpthumb.php
2026-01-19T17:40:50.655384000+0100	192.168.1.104	/wordpress/wp-content/plugins/wp-marketplace/libs/timthumb.phptimthumb.php
2026-01-19T17:40:50.656619000+0100	192.168.1.104	/wordpress/wp-content/plugins/wpmarketplace/timthumb.php
2026-01-19T17:40:50.658868000+0100	192.168.1.104	/wordpress/wp-content/plugins/wp-mobile-detector/timthumb.php
2026-01-19T17:40:50.658889000+0100	192.168.1.104	/wordpress/wp-content/plugins/wp-mobile-detector/thumb.php
2026-01-19T17:40:50.661059000+0100	192.168.1.104	/wordpress/wp-content/plugins/wp-pagenavi/functions/timthumb.php
2026-01-19T17:40:50.661060000+0100	192.168.1.104	/wordpress/wp-content/plugins/wp-pagenavi/functions/thumb.php
2026-01-19T17:40:50.661061000+0100	192.168.1.104	/wordpress/wp-content/plugins/wp-pagenavi/inc/thumb.php
2026-01-19T17:40:50.662948000+0100	192.168.1.104	/wordpress/wp-content/plugins/wp-pagenavi/inc/timthumb.php
2026-01-19T17:40:50.663571000+0100	192.168.1.104	/wordpress/wp-content/plugins/wp-pagenavi/scripts/thumb.php
2026-01-19T17:40:50.664200000+0100	192.168.1.104	/wordpress/wp-content/plugins/wp-pagenavi/scripts/timthumb.php
2026-01-19T17:40:50.665449000+0100	192.168.1.104	/wordpress/wp-content/plugins/wp-pagenavi/thumb.php
2026-01-19T17:40:50.667482000+0100	192.168.1.104	/wordpress/wp-content/plugins/wp-pagenavi/timthumb.phptimthumb.php
2026-01-19T17:40:50.667503000+0100	192.168.1.104	/wordpress/wp-content/plugins/wp-pagenavi/timthumb.php
2026-01-19T17:40:50.671314000+0100	192.168.1.104	/wordpress/wp-content/plugins/wp_rokbox/thumb.php
2026-01-19T17:40:50.671937000+0100	192.168.1.104	/wordpress/wp-content/plugins/wp_rokbox/thumb.phpthumb.php
2026-01-19T17:40:50.671937000+0100	192.168.1.104	/wordpress/wp-content/plugins/wp_rokbox/thumb.phptimthumb.php
2026-01-19T17:40:50.672563000+0100	192.168.1.104	/wordpress/wp-content/plugins/wp_rokbox/timthumb.php
2026-01-19T17:40:50.672565000+0100	192.168.1.104	/wordpress/wp-content/plugins/wp_rokintroscroller/thumb.php
2026-01-19T17:40:50.675465000+0100	192.168.1.104	/wordpress/wp-content/plugins/wp_rokintroscroller/thumb.phpthumb.php
2026-01-19T17:40:50.676095000+0100	192.168.1.104	/wordpress/wp-content/plugins/wp_rokintroscroller/thumb.phptimthumb.php
2026-01-19T17:40:50.677332000+0100	192.168.1.104	/wordpress/wp-content/plugins/wp_rokmicronews/thumb.php
2026-01-19T17:40:50.677332000+0100	192.168.1.104	/wordpress/wp-content/plugins/wp_rokintroscroller/timthumb.php
2026-01-19T17:40:50.680282000+0100	192.168.1.104	/wordpress/wp-content/plugins/wp_rokmicronews/thumb.phpthumb.php
2026-01-19T17:40:50.680316000+0100	192.168.1.104	/wordpress/wp-content/plugins/wp_rokmicronews/thumb.phptimthumb.php
2026-01-19T17:40:50.680935000+0100	192.168.1.104	/wordpress/wp-content/plugins/wp_rokmicronews/timthumb.php
2026-01-19T17:40:50.681554000+0100	192.168.1.104	/wordpress/wp-content/plugins/wp_roknewspager/thumb.php
2026-01-19T17:40:50.682173000+0100	192.168.1.104	/wordpress/wp-content/plugins/wp_roknewspager/thumb.phpthumb.php
2026-01-19T17:40:50.683408000+0100	192.168.1.104	/wordpress/wp-content/plugins/wp_roknewspager/thumb.phptimthumb.php
2026-01-19T17:40:50.685040000+0100	192.168.1.104	/wordpress/wp-content/plugins/wp_roknewspager/timthumb.php
2026-01-19T17:40:50.686538000+0100	192.168.1.104	/wordpress/wp-content/plugins/wp_rokstories/thumb.php
2026-01-19T17:40:50.687166000+0100	192.168.1.104	/wordpress/wp-content/plugins/wp_rokstories/timthumb.php
2026-01-19T17:40:50.687166000+0100	192.168.1.104	/wordpress/wp-content/plugins/wp_rokstories/thumb.phptimthumb.php
2026-01-19T17:40:50.687168000+0100	192.168.1.104	/wordpress/wp-content/plugins/wp_rokstories/thumb.phpthumb.php
2026-01-19T17:40:50.689530000+0100	192.168.1.104	/wordpress/wp-content/plugins/wps3slider/scripts/timthumb.php
2026-01-19T17:40:50.691967000+0100	192.168.1.104	/wordpress/wp-content/plugins/wptap-news-press-themeplugin-for-iphone/include/timthumb.php
2026-01-19T17:40:50.691992000+0100	192.168.1.104	/wordpress/wp-content/plugins/wp-thumbie/timthumb.php
2026-01-19T17:40:50.692613000+0100	192.168.1.104	/wordpress/wp-content/plugins/wp-slick-slider/includes/timthumb/timthumb.php
2026-01-19T17:40:50.692613000+0100	192.168.1.104	/wordpress/wp-content/plugins/yd-export2email/timthumb.php
2026-01-19T17:40:50.696362000+0100	192.168.1.104	/wordpress/wp-content/plugins/yd-recent-posts-widget/timthumb/timthumb.php
2026-01-19T17:40:50.697688000+0100	192.168.1.104	/wordpress/wp-content/plugins/zingiri-web-shop/fws/addons/timthumb/thumb.php
2026-01-19T17:40:50.697687000+0100	192.168.1.104	/wordpress/wp-content/plugins/zingiri-web-shop/timthumb.php
2026-01-19T17:40:50.697688000+0100	192.168.1.104	/wordpress/wp-content/plugins/zingiri-web-shop/fws/addons/timthumb/timthumb.php
2026-01-19T17:40:51.015656000+0100	192.168.1.104	/wordpress/wp-content/plugins/dump.sql

```

Or in WireShark GUI:
![](/images/7b2ddc62cccc994c0168347b16feb434.png)

Starting from the top lets dump content of social warfare plugins ( first on the list) readme.txt, and convert it from hex to binary/ascii with xxd -r -p:

```bash
~/Vault/isec/ctf/knight2k26/net100-exploitation  ✓ $ tshark -r pcap2.pcapng -Y 'http.request.uri contains "social-warfare/readme.txt"' -T fields -e http.file_data | xxd -r -p

=== WordPress Social Sharing Plugin - Social Warfare ===
Contributors: holas84, dustinwstout, webinator, warfareplugins, nutsandboltsmedia, cdegraff1, ckmahoney
Tags: sharing buttons, social media share, floating share buttons, facebook share, google plus share, linkedin share, pin it, pinterest save, mix button, tweet button, twitter share, click to tweet, social sharing buttons, social share, social sharing, social media sharing, wordpress social sharing plugin, social sharing plugin, share buttons, share counts
Requires at least: 4.5.0
Tested up to: 5.1
Stable tag: 3.5.2
Requires PHP: 5.6
License: GNU General Public License v2.0 or later

The most beautiful, responsive, lightning fast social share buttons built to boost shares and drive more traffic without slowing down your site.

== Description ==

```


We see that version is: **3.5.2**

### Flag

Flag is **KCTF{social_warfare_3.5.2}**

![](/images/26ccef2aed200123433953b4962922fc.png)


## Task 3 - Post Exploitation

```
## Post-Exploitation

### 100 Points

Author

After exploiting the vulnerability, the attacker established a persistent connection back to their command and control server. Analyze the traffic to identify the HTTP port used for the initial payload delivery and the port used for the reverse shell connection.

Download: [pcap3.pcapng](https://drive.google.com/file/d/1Xr1onCDIvTvMviH1k16mIjH2P2tfQZuq/view?usp=sharing)

**Flag Format: KCTF{httpPort_revshellPort}**
```


https://drive.google.com/file/d/1Xr1onCDIvTvMviH1k16mIjH2P2tfQZuq/view?usp=sharing


### pcap3.pcapng - Payload Analysis

Since it's wordpress in question, i assumed that shell was uploaded from that Social Warfare plugin we already figured out previously, which means by http.

I started filtering out by POST and GET requests, and just looking around. It couldn't be more obvious:
![](/images/2a7ba68a114d37e816a2f96a8b85285b.png)

This already gives us HTTP port for the payload **8786**, which is half of the flag. Now we only need to find the reverse shell port.

To narrow it down we want to:
- look after timestamp of a payload, since revese shell can only be invoked after uploading obviously, in screenshot you can see timestamp: **882**
   `( frame.time_relative > 882)`
   
- `!(tcp.port==80 || tcp.port==8767)` - exclude port 80 and payload port 8786
 - `ip.src==192.168.1.102`  - Only traffic from the victim.
- `ip.dst==192.168.1.104` - Only traffic going to the attacker.

We will also filter multiple mentions of the same port number with sort -u :

```bash
~/Vault/isec/ctf/knight2k26/net100-exploitation  ✓ $ tshark -r pcap3.pcapng -Y "ip.src==192.168.1.102 && ip.dst==192.168.1.104 && tcp && frame.time_relative>882 && !(tcp.port==80 || tcp.port==8767)" -T fields -e tcp.srcport -e tcp.dstport | sort -u

     9576

```

And there it is, reverse shell port **9576**

**Note**:
You can filter with `sort | uniq -c` if you want to display number of packets sent and ephemeral port.
### Flag

Flag is: KCTF{8767_9576}

![](/images/7be91c4aef1cc1f6451c0cd389d0ef49.png)

## Task 4 - Database Theft

```
## Database Credentials Theft

### 100 Points

Author

The attacker's ultimate goal was to access our database. During the post-exploitation phase, they managed to extract database credentials from the compromised system. Find the database username and password that were exposed.

> Use pcap3.pcapng file to solve this challenge.

**Flag Format: KCTF{username_password}**

_**Author: TareqAhamed (0xt4req)**_
```

### pcap3.pacpng -  Reverse Shell Data Analysis

This was the easiest one so far.
Since we know from previous task that reverse shell was running on 9576, lets only dump TCP stream from it, and convert it from HEX to Binary/ASCII.

That way we can basically see what was the attacker running in the reverse shell:
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

And, well, yes that's a password and username right there.

### Flag

Flag is: **KCTF{wpuser_wp@user123}**

![](/images/7a483ecec97a116e2f38fc8f665e5570.png)
