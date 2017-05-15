# DCS17CTF S21Sec tasks and writeups
Tasks, scripts and writeups of most fun or interesting tasks of DCS17CTF (S21SEC)
https://challenge.s21sec.com

#### MAuritania – 400 points

![](https://i1.wp.com/blogs.tunelko.com/wp-content/uploads/2017/05/MAURITANIA.jpg?w=844&ssl=1)

**First Run**

Before run we try to inspect binary strings (strings ftw! – n00b says). We clearly see a weird string that could match our password. But, this is not so (so) easy!.

![](https://i2.wp.com/blogs.tunelko.com/wp-content/uploads/2017/05/rev2-strings.jpg?w=685&ssl=1)

**IDA Dissasembler**

Seems IDA could help on this simple task. All you have to do is open binary and get pseudo code from main function

![](https://i2.wp.com/blogs.tunelko.com/wp-content/uploads/2017/05/ida-rev2.jpg?w=661&ssl=1)

So it’s **simple XOR with 0x16 key on “paswd” variable**. Remember this weird string (**A1-C3bK4_2h5f8vE**)?  Yes, its xoring and result is our flag. For the task we can reproduce this for loop part and get output.

```
#include <stdio.h>
int main()
{
    char* paswd = "A1-C3bK4_2h5f8vE"; 
    int j; 
    printf("Tu flag es:"); 
  for ( j = 0; j < strlen(paswd); ++j )
    putchar((char)(paswd[j] ^ 0x16));
  return 0;
}
```

Finally easy flag ;)

![](https://i0.wp.com/blogs.tunelko.com/wp-content/uploads/2017/05/rev2-solver-1.jpg?w=973&ssl=1)
