#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include <unistd.h>
#include <stdbool.h>
int main(int argc, char ** argv)
{
	unsigned char key = 0xAA;
	bool valid = true;

	char * password = malloc(100);
        printf("Enter new password: ");
        scanf("%100s", password);
	int len = strlen(password);
	unsigned char passHex[] = {0xDA, 0xCB, 0xD9, 0xD9, 0xDD, 0xC5,0xD8, 0xCE};
        if(len != sizeof(passHex))
	{
		valid = false;
	}
	for(int i = 0; i < sizeof (passHex); i++)
        {
		unsigned char temp =  password[i] ^ passHex[i];
		if(temp != key)
		{
			valid = false;
			break;
		}
        }
	if(valid == true)
	{
		printf("Password accepted: %s", password);
	}
	else
	{
		printf("Password is incorrect!");
	}

}

