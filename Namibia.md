# DCS17CTF S21Sec tasks and writeups
Tasks, scripts and writeups of most fun or interesting tasks of DCS17CTF (S21SEC)
https://challenge.s21sec.com

#### Namibia – 450 points

![](https://i2.wp.com/blogs.tunelko.com/wp-content/uploads/2017/05/NAMIBIA.jpg?w=843&ssl=1)

**SREC Motorola Firmware**

We can learn a lot from ctf tasks. Indeed there is a lot of encoding’s format like [Motorola SREC](https://es.wikipedia.org/wiki/SREC). Basically encodes a header, data, indexes that points program execution, etc …


S00600004844521B
S224000000484452301CA03700B7EE571C010001001C00000000000000000000006D000080B7
S2240000200058FC28000000000000040295000E0FF83FD5D150C7E1D537C034840C61304E43
S224000040FFFD7222F02A68DF477128FBD7F618CA60FFB3A4CC96AE22A5BD9C552B444D48E1
S224000060EDB9C8FC0FC207B42FECFD59EE850345EFBC6C824FC16473007346892EC931C8A7
S224000080607430577EA52A7184A453193A596FCC28FBDEFF4140B103B1995839B99884B942
S2240000A0EBF15E953D84030DED73309D4679F3CBBE3A91156558B6385A9E5773121F8F889E
S2240000C08C51A33CE05BDCA7D361CD642D1E63FE5F0E6BE461AD9F4682787368F14D4B3B48
S2240000E083F7CAD0E083F38B7A64DF734D85694BB161DEC760F2C94699D1A8D22A05A3FE84
S224000100F780943EE1016E8397C7FF6D8A6E469759039F408238E2DA86EC39CF3A5EBCABF5
S224000120762B1BB6CFC9E4385DE8CBB94C094BE1207073579557E8F76C04F159A0A0D74410
....

![](https://i0.wp.com/blogs.tunelko.com/wp-content/uploads/2017/05/srec-format.jpg?w=728&ssl=1)

Task is asking us about **serial number of local SSL web administrative page**. So, if i’m not wrong, inside that file must be present a web server with some cert.pem file. First step is dump a binary file from srec format. We can use python library “bincopy”. There is another tools on Internet related to srec format for several srec’s types, but for me python works.

```
import bincopy

f = bincopy.BinFile()
f.add_srec_file("firmware.image")
b = f.as_binary()
print b
```

Let’s see inside srec.bin file generate using binwalk.

![](https://i2.wp.com/blogs.tunelko.com/wp-content/uploads/2017/05/firm-sq.jpg?resize=768%2C74&ssl=1)

Interesting, an squashfs filesystem, so let’s extract with binwalk (-E) and see inside.

![](https://i2.wp.com/blogs.tunelko.com/wp-content/uploads/2017/05/firm-sq2.jpg?w=695&ssl=1)


Looks like a www dir, seems we are near solution, find a cert.pem and extract SSL serial.

``` 

/etc/ ... 
 
4,0K drwxrwx--- 1 root vboxsf 4,0K jul 25  2008 .
4,0K drwxrwx--- 1 root vboxsf 4,0K jul 25  2008 ..
 512 -rwxrwx--- 1 root vboxsf   64 jul 25  2008 ld.so.cache
 512 -rwxrwx--- 1 root vboxsf   99 jul 25  2008 ld.so.conf
 512 -rwxrwx--- 1 root vboxsf  147 jul 25  2008 local.tar.bz2
   0 drwxrwx--- 1 root vboxsf    0 jul 25  2008 config
 512 -rwxrwx--- 1 root vboxsf  253 jul 25  2008 ipkg.conf
   0 drwxrwx--- 1 root vboxsf    0 jul 25  2008 langpack
1,0K -rwxrwx--- 1 root vboxsf  578 jul 25  2008 postinit
2,0K -rwxrwx--- 1 root vboxsf 1,8K jul 25  2008 preinit
   0 drwxrwx--- 1 root vboxsf    0 jul 25  2008 kaid
1,5K -rwxrwx--- 1 root vboxsf 1,4K jul 25  2008 ethertypes
 512 -rwxrwx--- 1 root vboxsf   30 jul 25  2008 fstab
   0 drwxrwx--- 1 root vboxsf    0 jul 25  2008 init.d
 512 -rwxrwx--- 1 root vboxsf  491 jul 25  2008 motd
1,5K -rwxrwx--- 1 root vboxsf 1,4K jul 25  2008 network.overrides
 512 -rwxrwx--- 1 root vboxsf  512 jul 25  2008 patchtable.bin
 512 -rwxrwx--- 1 root vboxsf  198 jul 25  2008 profile
6,0K -rwxrwx--- 1 root vboxsf 5,7K jul 25  2008 protocols
 12K -rwxrwx--- 1 root vboxsf  12K jul 25  2008 services
   0 drwxrwx--- 1 root vboxsf    0 jul 25  2008 l7-protocols
1,5K -rwxrwx--- 1 root vboxsf 1,5K jul 25  2008 lease_update.sh
1,0K -rwxrwx--- 1 root vboxsf  810 jul 25  2008 cert.pem
 512 -rwxrwx--- 1 root vboxsf  493 jul 25  2008 key.pem
1,0K -rwxrwx--- 1 root vboxsf  561 jul 25  2008 privkey.pem
1,6M -rwxrwx--- 1 root vboxsf 1,6M jul 25  2008 www
```

openssl let you see info about a certificate, so let’s use:

```
openssl x509 -in cert.pem -text
Certificate:
    Data:
        Version: 1 (0x0)
        Serial Number:
            a9:69:1d:aa:b9:8c:63:e4
    Signature Algorithm: sha1WithRSAEncryption
        Issuer: C = DE, ST = Saxon, L = Dresden, O = NewMedia-NET GmbH, OU = Division, CN = NewMedia-NET GmbH, emailAddress = info@dd-wrt.com
        Validity
            Not Before: Jul 26 02:44:18 2008 GMT
            Not After : Jul 24 02:44:18 2018 GMT
        Subject: C = DE, ST = Saxon, L = Dresden, O = NewMedia-NET GmbH, OU = Division, CN = NewMedia-NET GmbH, emailAddress = info@dd-wrt.com
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                Public-Key: (512 bit)
                Modulus:
                    00:d7:fe:10:78:dd:da:07:0b:23:9d:20:a0:07:96:
                    a5:b0:e8:98:2f:35:05:95:37:3c:0c:a3:7b:5f:81:
                    97:42:2b:f5:3b:20:8c:a2:5f:e9:53:ea:59:58:ac:
                    89:c9:35:f9:f5:58:c3:a1:d3:d1:68:e6:17:fa:71:
                    c6:c1:e0:50:75
                Exponent: 65537 (0x10001)
    Signature Algorithm: sha1WithRSAEncryption
         40:31:d6:4e:05:64:74:cf:2d:31:75:56:c9:74:14:65:22:dc:
         36:36:d5:ca:1f:6d:34:55:47:6f:c5:11:b0:16:ad:2e:69:21:
         43:28:8b:91:19:6b:c8:90:a7:4f:be:25:40:a8:f0:b7:bb:be:
         04:69:b1:86:77:3d:fa:9a:70:07
-----BEGIN CERTIFICATE-----
MIICKDCCAdICCQCpaR2quYxj5DANBgkqhkiG9w0BAQUFADCBmjELMAkGA1UEBhMC
REUxDjAMBgNVBAgTBVNheG9uMRAwDgYDVQQHEwdEcmVzZGVuMRowGAYDVQQKExFO
ZXdNZWRpYS1ORVQgR21iSDERMA8GA1UECxMIRGl2aXNpb24xGjAYBgNVBAMTEU5l
d01lZGlhLU5FVCBHbWJIMR4wHAYJKoZIhvcNAQkBFg9pbmZvQGRkLXdydC5jb20w
HhcNMDgwNzI2MDI0NDE4WhcNMTgwNzI0MDI0NDE4WjCBmjELMAkGA1UEBhMCREUx
DjAMBgNVBAgTBVNheG9uMRAwDgYDVQQHEwdEcmVzZGVuMRowGAYDVQQKExFOZXdN
ZWRpYS1ORVQgR21iSDERMA8GA1UECxMIRGl2aXNpb24xGjAYBgNVBAMTEU5ld01l
ZGlhLU5FVCBHbWJIMR4wHAYJKoZIhvcNAQkBFg9pbmZvQGRkLXdydC5jb20wXDAN
BgkqhkiG9w0BAQEFAANLADBIAkEA1/4QeN3aBwsjnSCgB5alsOiYLzUFlTc8DKN7
X4GXQiv1OyCMol/pU+pZWKyJyTX59VjDodPRaOYX+nHGweBQdQIDAQABMA0GCSqG
SIb3DQEBBQUAA0EAQDHWTgVkdM8tMXVWyXQUZSLcNjbVyh9tNFVHb8URsBatLmkh
QyiLkRlryJCnT74lQKjwt7u+BGmxhnc9+ppwBw==
-----END CERTIFICATE-----
```

And finally we get flag.

![](https://i2.wp.com/blogs.tunelko.com/wp-content/uploads/2017/05/firm-serial.jpg?resize=768%2C439&ssl=1)

**Flag: a9691daab98c63e4**


