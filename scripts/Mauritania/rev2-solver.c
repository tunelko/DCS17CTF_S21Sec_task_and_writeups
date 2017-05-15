#include <stdio.h>

int main()
{
    char* paswd = "A1-C3bK4_2h5f8vE"; 
    int j; 
    printf("Tu flag es:"); 
  for ( j = 0; j < strlen(paswd); ++j ) { 
    putchar((char)(paswd[j] ^ 0x16));
	}
    putchar(10) ; 
  return 0;
}
