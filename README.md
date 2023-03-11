# PyCript
<p align="center">
  <img src="https://i.ibb.co/KqGXSq0/Py-Cript-Banner.png" />
</p>



Pycript is a Burp Suite extension that enables users to encrypt and decrypt requests for manual and automated application penetration testing. It also allows users to create custom encryption and decryption logic using JavaScript and Node.js, allowing for a tailored encryption/decryption process for specific needs.


[![Deploy](https://github.com/Anof-cyber/PyCript-Docs/actions/workflows/static.yml/badge.svg)](https://github.com/Anof-cyber/PyCript-Docs/actions/workflows/static.yml)
![GitHub](https://img.shields.io/github/license/Anof-cyber/APTRS)
![GitHub closed issues](https://img.shields.io/github/issues-closed/Anof-cyber/PyCript)
[![](https://img.shields.io/static/v1?label=Sponsor&message=%E2%9D%A4&logo=GitHub&color=%23fe8e86)](https://github.com/sponsors/Anof-cyber)
[![](https://i.ibb.co/qsV4mb9/twitter-2.png)](https://twitter.com/ano_f_)[![](https://i.ibb.co/89LKTrL/linkedin-1.png)](https://www.linkedin.com/in/sourav-kalal/)


## Support

<a href="https://www.buymeacoffee.com/AnoF"><img src="https://img.buymeacoffee.com/button-api/?text=Buy me a coffee&emoji=&slug=AnoF&button_colour=FF5F5F&font_colour=ffffff&font_family=Arial&outline_colour=000000&coffee_colour=FFDD00" /></a>


## Documentation

<a href="https://pycript.souravkalal.tech/#/"><img src="https://i.ibb.co/NLTJ6MR/70686099-3855f780-1c79-11ea-8141-899e39459da2.png" alt="70686099-3855f780-1c79-11ea-8141-899e39459da2" border="0"></a>

## Reference
- [Bypassing Asymmetric Client Side Encryption Without Private Key](https://infosecwriteups.com/bypassing-asymmetric-client-side-encryption-without-private-key-822ed0d8aeb6)
- [Manipulating Encrypted Traffic using PyCript](https://infosecwriteups.com/manipulating-encrypted-traffic-using-pycript-b637612528bb)

## Requirements

- Node JS
- Burp Suite with Jython
    
## Features

- [X] Encrypt & Decrypt the Selected Strings from Request Response
- [X] View and Modify the encrypted request in plain text
- [X] Decrypt Multiple Requests 
- [X] Perform Burp Scanner, Sql Map, Intruder Bruteforce or any Automation in Plain Text
- [X] Auto Encrpyt the request on the fly
- [X] Complete freedom for encryption and decryption logic
- [X] Ability to handle encryption and decryption even with Key and IV in Request Header or Body


## Demo Code
Repository for More Encryption Decryption examples [Code Repository ](https://github.com/Anof-cyber/PyCript-Template)

### Encryption Code

```javascript
var CryptoJS = require("crypto-js");
const program = require("commander");
const { Buffer } = require('buffer');
program
  .option("-d, --data <data>", "Data to process")
  .parse(process.argv);
  
const options = program.opts();
const plaintext = Buffer.from(options.data, 'base64').toString('utf8');

var key = "1234"
var iv = "1234"
var encryptedbytes  = CryptoJS.AES.encrypt(plaintext, CryptoJS.enc.Utf8.parse(key),
{	
	keySize: 128 / 8,
	iv:  CryptoJS.enc.Utf8.parse(iv),
    mode: CryptoJS.mode.CBC
});
var Encryptedtext = encryptedbytes.toString();

console.log(Encryptedtext)
```

### Decryption Code

```javascript
var CryptoJS = require("crypto-js");
const program = require("commander");
const { Buffer } = require('buffer');
program
  .option("-d, --data <data>", "Data to process")
  .parse(process.argv); 
const options = program.opts();
var ciphertext = Buffer.from(options.data, 'base64').toString('utf8');


var key = "1234"
var iv = "1234"
var decryptedbytes  = CryptoJS.AES.decrypt(ciphertext, CryptoJS.enc.Utf8.parse(key),
{	
	keySize: 128 / 8,
	iv:  CryptoJS.enc.Utf8.parse(iv),
    mode: CryptoJS.mode.CBC
});
var plaintext = decryptedbytes.toString(CryptoJS.enc.Utf8);

console.log(plaintext)
```

## Roadmap

- [ ] Response Encryption & Decryption
- [ ] Support for GET Paramters
- [ ] Allowing Edit Headers for Request Type ```Custom Request```
- [ ] Supporting multiple languages for encryption and decryption 



## Screenshots

![PyCript](https://raw.githubusercontent.com/Anof-cyber/PyCript-Docs/main/image/JsonValue%20Example%201.gif)
![PyCript](https://raw.githubusercontent.com/Anof-cyber/PyCript-Docs/main/image/Whole%20Body%20Example%202.gif?token=GHSAT0AAAAAAB5OOGKCUVH5WYGGGMSN3WMCY6O2WTQ)
![PyCript](https://raw.githubusercontent.com/Anof-cyber/PyCript-Docs/main/image/String-Encryption-Decryption.gif?token=GHSAT0AAAAAAB5OOGKDFSDHT43XDE4F3ZXIY6O2XGQ)
![PyCript](https://raw.githubusercontent.com/Anof-cyber/PyCript-Docs/main/image/Whole%20Body%20Example%201.gif?token=GHSAT0AAAAAAB5OOGKCY6J7HYLSEDMKQBVQY6O2XRA)

![PyCript](https://raw.githubusercontent.com/Anof-cyber/PyCript-Docs/main/image/Pyript.png?token=GHSAT0AAAAAAB5OOGKCW77N7FYJXK2IJEY4Y6OYV6A)

![PyCript](https://raw.githubusercontent.com/Anof-cyber/PyCript-Docs/main/image/Pyript%20Decrypted%20Request.png?token=GHSAT0AAAAAAB5OOGKD2SOEVMKCWQ4WPYVAY6OYTOQ)
![PyCript](https://raw.githubusercontent.com/Anof-cyber/PyCript-Docs/main/image/Pyript%20Request%20Tab.png?token=GHSAT0AAAAAAB5OOGKCQ3CVRT5642X73PCSY6OYVSA)



