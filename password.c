//objdump -Mintel -d ./password
#include<stdio.h>
#include<stdlib.h>
#include<string.h>


int main(int argc, char ** argv)
{
	int number = 10;
	char *password = "password\0";
	int num = 999;
	char * pass =  malloc(100);
	printf("Enter the secret number: ");
	scanf("%d", &num);
	printf("Enter the secret password: ");
	scanf("%s", pass);

	if( strcmp(pass, password) == 0 && num == number)
	{
		printf("it's a match");
	}
	else
	{
	printf("not a match!");
	}

}
