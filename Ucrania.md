# DCS17CTF S21Sec tasks and writeups
Tasks, scripts and writeups of most fun or interesting tasks of DCS17CTF (S21SEC)
https://challenge.s21sec.com

#### Ucrania – 450 points 

Initial analisis with hexdump 

![](https://i2.wp.com/blogs.tunelko.com/wp-content/uploads/2017/05/ucrania-hexdump.jpg?zoom=1.25&resize=692%2C606&ssl=1)

Some indicates that is a image ciphered, isn’t it? :P. Need to know what cipher and in case of ECB (assumption) we need resolution, because BMP encodes it on file.

See this previous writeup to better understand: https://github.com/jesstess/tinyctf/blob/master/ecb/ecb.md

Making use of this script (https://github.com/doegox/ElectronicColoringBook/blob/master/ElectronicColoringBook.py) only need to ‘brute’ X resolution, from 800-1200 and wait for a valid image:

```
for x in {800..1200..100}; do python ElectronicColoringBook.py -x $x image_bffd6d7169826614c3f23cf0a7bdf997.enc ; done
```

It produces several images but one that we can read.

![](https://i2.wp.com/blogs.tunelko.com/wp-content/uploads/2017/05/ucrania-img.jpg?resize=768%2C285&ssl=1)

**Flag: USECBC!**