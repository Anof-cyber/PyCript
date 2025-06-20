# PyCript
<p align="center">
  <img src="https://i.ibb.co/KqGXSq0/Py-Cript-Banner.png" />
</p>



Pycript is a Burp Suite extension that enables users to encrypt and decrypt requests and response for manual and automated application penetration testing. It also allows users to create custom encryption and decryption logic using JavaScript, Python and Java, allowing for a tailored encryption/decryption process for specific needs.


[![Deploy](https://github.com/Anof-cyber/PyCript-Docs/actions/workflows/static.yml/badge.svg)](https://github.com/Anof-cyber/PyCript-Docs/actions/workflows/static.yml)
![GitHub](https://img.shields.io/github/license/Anof-cyber/APTRS)
![GitHub closed issues](https://img.shields.io/github/issues-closed/Anof-cyber/PyCript)
[![](https://img.shields.io/static/v1?label=Sponsor&message=%E2%9D%A4&logo=GitHub&color=%23fe8e86)](https://github.com/sponsors/Anof-cyber)
![GitHub Release Date](https://img.shields.io/github/release-date/anof-cyber/PyCript?style=plastic)
![GitHub release (latest by date including pre-releases)](https://img.shields.io/github/v/release/anof-cyber/PyCript?include_prereleases)
![GitHub last commit](https://img.shields.io/github/last-commit/Anof-cyber/PyCript)
[![](https://i.ibb.co/qsV4mb9/twitter-2.png)](https://twitter.com/ano_f_)[![](https://i.ibb.co/89LKTrL/linkedin-1.png)](https://www.linkedin.com/in/sourav-kalal/)


## Documentation

<a href="https://pycript.souravkalal.tech/#/"><img src="https://i.ibb.co/NLTJ6MR/70686099-3855f780-1c79-11ea-8141-899e39459da2.png" alt="70686099-3855f780-1c79-11ea-8141-899e39459da2" border="0"></a>

## Reference
- [Youtube - PyCript Demo](https://www.youtube.com/watch?v=J8KE5VR8yDk)
- [Bypassing Asymmetric Client Side Encryption Without Private Key](https://infosecwriteups.com/bypassing-asymmetric-client-side-encryption-without-private-key-822ed0d8aeb6)
- [Manipulating Encrypted Traffic using PyCript](https://infosecwriteups.com/manipulating-encrypted-traffic-using-pycript-b637612528bb)


## Requirements

- Node JS / Python / Java
- Burp Suite with Jython
    
## Features

- [X] [NEW] **Improved JSON readability:** Decrypted JSON body is now prettified in the PyCript tab.
- [X] [FIX] **Fixed encoding issue with Arabic characters:** Base64 encoding now correctly preserves Arabic/non-ASCII characters.
- [X] Encrypt & Decrypt the Selected Strings from Request Response
- [X] View and Modify the encrypted request in plain text
- [X] Decrypt Multiple Requests 
- [X] Perform Burp Scanner, SQL Map, Intruder Bruteforce or any Automation in Plain Text
- [X] Auto Encrpyt the request on the fly
- [X] Complete freedom for encryption and decryption logic
- [X] Ability to handle encryption and decryption even with Key and IV in Request Header or Body

## Roadmap

- [X] Response Encryption & Decryption
- [X] Support for GET Paramters
- [X] Allowing Edit Headers for Request Type ```Custom Request```
- [X] Supporting multiple languages for encryption and decryption 




## Screenshots

![PyCript](https://github.com/Anof-cyber/PyCript-Docs/blob/gh-pages/0.2/assets/Complete%20Body%20-%20Example%201.gif?raw=true)

![PyCript](https://github.com/Anof-cyber/PyCript-Docs/blob/gh-pages/0.2/assets/Complete%20Body%20-%20Example%202.gif?raw=true)


![PyCript](https://github.com/Anof-cyber/PyCript-Docs/blob/gh-pages/0.2/assets/Custom%20Request%20-%20Example%201.gif?raw=true)


![PyCript](https://github.com/Anof-cyber/PyCript-Docs/blob/gh-pages/0.2/assets/Edit%20Header%20-%20Example%201.gif?raw=true)

![PyCript](https://github.com/Anof-cyber/PyCript-Docs/blob/gh-pages/0.2/assets/Paramter%20Value%20-%20Example%201.gif?raw=true)

![PyCript](https://github.com/Anof-cyber/PyCript-Docs/blob/gh-pages/0.2/assets/Paramter%20Key%20and%20value%20-%20Example%201.gif?raw=true)
