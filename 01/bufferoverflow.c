#include <stdio.h>
#include <string.h>

void exploit(char *InputString);

int main(void)
{
    char buff[15];

	printf("      Try: AAAAAAAAAAAAAAAAAAAAA (16x'A' + 5x'A')\n");
	printf("Don't-Try: AAAAAAAAAAAAAAAAAAAAAAAAA (16x'A' + 8x'A' + 'A')\n");
	printf("      Try: AAAAAAAAAAAAAAAAAAAAAAAA (16 + 8) x 'A'\n");
    printf("\nEnter the Text : \n");
    gets(buff);
    
    exploit(buff);

    return 0;
}

void exploit(char *InputString) {
	char buf1[5]; // uses 8 byte?
	char buf2[5]; // uses 16 byte
	
	strcpy(buf1, "     ");
	strcpy(buf2, "     ");
	strcpy(buf2, InputString);
	
	printf("input: [%p]'%s'\n", InputString, InputString);
	printf("buf1: [%p]'%s'\n", buf1, buf1);
	printf("buf2: [%p]'%s'\n", buf2, buf2);
}
