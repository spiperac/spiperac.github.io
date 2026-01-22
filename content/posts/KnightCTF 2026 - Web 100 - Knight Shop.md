+++
date = 2026-01-21
description ="KnightCTF 2026 - Web 100 - Knight Shop"
title = "KnightCTF 2026 - Web 100 - Knight Shop"
[taxonomies]
tags = ["ctf", "web", "burp"]
+++
## Task

```
## Knight Shop Again

### 100 Points

Author

A modern e-commerce platform for medieval equipment. I know you'll figure it out.

> [http://23.239.26.112:8087/](http://23.239.26.112:8087/)

**Flag Format: KCTF{Fl4g_heR3}**

```

## Enumeration

```
~  ✓ $ whatweb http://23.239.26.112:8087
http://23.239.26.112:8087 [200 OK] Country[UNITED STATES][US], HTML5, IP[23.239.26.112], Script, Title[Knight Shop - Premium Medieval Equipment], X-Powered-By[Express]
```

View page source shows one JS file import:

```html
<script defer="defer" src="/static/js/main.b42977dd.js"></script>
```

Which further confirms that this is in fact **ReactJS** App:
```js
/*! For license information please see main.b42977dd.js.LICENSE.txt */
(()=>{"use strict";var e={43(e,t,n){e.exports=n(202)},153(e,t,n){var r=n(43),a=Symbol.for("react.element")....
```

Since the file is **minified**, we can **beautify** it and also try to get the debug files if they're left after building the, those should be corresponding .js.map files:

```console
~/Vault/isec/ctf/knight2k26/web100-shop  ✓ $ wget http://23.239.26.112:8087/static/js/main.b42977dd.js.map
--2026-01-22 21:44:28--  http://23.239.26.112:8087/static/js/main.b42977dd.js.map
Connecting to 23.239.26.112:8087... connected.
HTTP request sent, awaiting response... 200 OK
Length: 839655 (820K) [application/json]
Saving to: ‘main.b42977dd.js.map.1’

main.b42977dd.js.map          100%[=======================================================>] 819.98K  1.08MB/s    in 0.7s

2026-01-22 21:44:29 (1.08 MB/s) - ‘main.b42977dd.js.map.1’ saved [839655/839655]

```

![](/images/b274505293ae2b8b1cbd369ccea2b860.png)

Opening a .js.map file shows us all of the imports and their **sources** in this ReactJS app.
Ignoring default imports, we're mostly interested in App.js, index.js and vendor.js.

App.js obfuscation with `\n` instead of new lines, and all of the quotes escaped can be fixed easily in neovim ( or whatever you use).

```
:%s/\\n//g
:%s/\\"/"/g
```

Running these two commands in neovim clears up the code, and makes it readable.

## Vulnerability

Looking around App.js for "flag" string i've found interesting function inside a shop logic.
```js
  const handleCheckout = async () => {
    setMessage('');
    
    const res = await fetch('/api/checkout', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ 
        discountCode: discountCount > 0 ? coupon : '',
        discountCount: discountCount 
      })
    });
    
    const data = await res.json();
    
    if (res.ok) {
      setUser({ ...user, balance: data.balance });
      setCart([]);
      setDiscountCount(0);
      
      if (data.flag) {
        setMessage(`🎉 Purchase successful! Your flag: ${data.flag}`);
      } else {
        setMessage('✅ Purchase successful!');
      }
      
      setTimeout(() => navigate('/orders'), 2000);
    } else {
      setMessage(`❌ ${data.error}`);
    }
  };

```

This function is used to handle checkout, calculate discount if discount code is applied.
In case of purchase, and data returned as response containing `flag` it will print out the flag.

Function which handles coupon application is **applyCoupon**:
```js
  const applyCoupon = () => {
    const result = processTransaction(coupon);
    if (result.valid) {
      setDiscountCount(prev => prev + 1);
      setMessage('✅ Coupon applied! 25% discount added.');
    } else {
      setMessage('❌ Invalid coupon code');
    }
  };
```

and **processTransaction** is imported at the top from **vendor**.js:

```js
import { processTransaction } from './utils/vendor';
```

Opening vendor.js file, we also need to replace `\n` with proper new lines.
Looking for **processTransaction** leads us to:
```js
export function processTransaction(input) {
  const result = _0x1a8c(input);
  return result;
}

...

function _0x1a8c(input) {
  const base = [75, 78, 73, 71, 72, 84];
  const suffix = [50, 53];
  
  if (!input || input.length < 5) return { valid: false };
  
  const prefix = input.substring(0, 6);
  const ending = input.substring(6);
  
  let match = true;
  for (let i = 0; i < 6; i++) {
    if (prefix.charCodeAt(i) !== base[i]) {
      match = false;
      break;
    }
  }
  
  if (match && ending.length === 2) {
    if (ending.charCodeAt(0) === suffix[0] && ending.charCodeAt(1) === suffix[1]) {
      const cookieName = 'promo_applied';
      const existingCookie = document.cookie.split(';').find(c => c.trim().startsWith(cookieName + '='));
      
      if (existingCookie) {
        return { valid: false };
      }
      
      document.cookie = cookieName + '=1; path=/';
      return { valid: true, code: input };
    }
  }
  
  return { valid: false };
}
```

So what **_0x1a8c** basically does is:

- Just converts prefix and suffix from decimal value to ascii string
  ```
	base = [75,78,73,71,72,84] → ASCII = K N I G H T 
	suffix = [50,53] → ASCII = 2 5
  ```
  
  - If the discount code is applied successfully it will set the cookie promo_applied to prevent reuse of the same coupon code.

The problem is **promo_applied** cookie is set on a client side, and can be manipulated.
From here on, it's pretty trivial to exploit this.

## Exploitation

First we need to create an account.

![](/images/aa8e6936e0a3dbd74def96680c8ae214.png)

Add an item to the card and go the the Cart page:

![](/images/a42a257330ce2c6d51d4a1ce433296db.png)

Now we will apply the coupon code: **KNIGHT25**.
But even with that discount we wont have enough balance to place an order.

![](/images/514208b8adc53c06be123441054240bb.png)

And if we try to apply coupon again we get `Invalid Coupon code`
![](/images/023a695faa6cb166c317e6ea5380f1b7.png)

Now we can just clear out the cookie set by the App from the browser, and reapply the same coupon.
![](/images/3ccbba232e6f4a7d1ef5017b2ad11492.png)

And it works!
Clicking on checkout should give us the flag:

![](/images/b1524d955909d3b3092b433fbd5b13c4.png)

## Flag

Flag is: **KCTF{kn1ght_c0up0n_m4st3r_2026}**

