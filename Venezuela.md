# DCS17CTF S21Sec tasks and writeups
Tasks, scripts and writeups of most fun or interesting tasks of DCS17CTF (S21SEC)
https://challenge.s21sec.com

#### Venezuela – 400 points

![](https://i0.wp.com/blogs.tunelko.com/wp-content/uploads/2017/05/VENEZUELA.jpg?w=847&ssl=1)

This time we have a python script to cipher text and ciphered file. The contents of the python:

```python
import sys, string
tcharset = string.lowercase + ' ,:.'
kcharset = [chr(x) for x in range(32,48) + range(58,65) + range(91,97) + range(123,127)]
for linea in sys.stdin:
    print ''.join([kcharset[tcharset.index(x)] for x in linea])
```

tcharset and kcharset are indeed used for “cipher” and “decipher” taking the index. Let’s see:

```python
tcharset: abcdefghijklmnopqrstuvwxyz ,:. 
kcharset: [' ', '!', '"', '#', '$', '%', '&', "'", '(', ')', '*', '+', ',', '-', '.', '/', ':', ';', '<', '=', '>', '?', '@', '[', '\\', ']', '^', '_', '`', '{', '|', '}', '~']
secret.txt: +.<^"(%; #.<^/.;^<><=(=>"(.-^<.-^".,/ ; !+$<^ ^+.<^"(%; #.<^/.;^=; -</.<("(.-{^$-^>-^"(%; #.^/.;^=; -</.<("(.-_^+ <^>-(# #$<^#$+^=$[=.^/+ -.^<.-^" ,!( # <^>< -#.^>- ^.;#$- "(.-^#(%$;$-=$^\^-.;, +,$-=$^! <= -=$^".,/+$) _^/$;.^+ <^>-(# #$<^$-^<.^,(<, <^-.^<.-^,.#(%(" # <{^ '''^\^=>^! -#$; ^$<`^ ]$;( *_^(< =< ^+>]

```
So a char on secret correspond a position in tcharset by the index of kcharset. And so on ... Modifying original script give us the secret text, swapping tcharset and kcharset:
```python 

import sys, string
tcharset = string.lowercase + ' ,:.'
kcharset = [chr(x) for x in range(32,48) + range(58,65) + range(91,97) + range(123,127)]
file = 'secreto_e47cadcff56cdcf8cb27eccb61dec09f.txt'
h = open(file, "r")
out=''
for linea in h.readline():
    #print ''.join([tcharset[kcharset.index(x)] for x in linea])
    out+=''.join([tcharset[kcharset.index(x)] for x in linea])

print out
```
Result:
```
$ python HacedorDeSecretos_d696737c071ddf468da3d8884ae15f03.py 
los cifrados por sustitucion son comparables a los cifrados por transposicion. en un cifrado por transposicion, las unidades del texto plano son cambiadas usando una ordenacion diferente y normalmente bastante compleja, pero las unidades en so mismas no son modificadas. ahhh y tu bandera es: azeriak, isatsa luze
```



**Flag: azeriak, isatsa luze**