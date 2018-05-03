#include<stdio.h>
#include<stdlib.h>
#include<string.h>

int main(int argc, char ** argv)
{

	char * password = "password";
	unsigned char key = 0xAA;
	int len = strlen(password);
	printf("Hex: ");
	for(int i = 0; i < len; i++)
	{
		printf("%X", password[i] ^ key);
	}

}
