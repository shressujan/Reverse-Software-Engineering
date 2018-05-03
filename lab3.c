#include<stdio.h>
#include<stdlib.h>
#include<string.h>
int main(int argc, char ** argv)
{
	char * string = malloc(100);
	printf("Enter a String in QWERTY format\n");
	scanf("%s", string);
	int len =  strlen(string);
	printf("In Dvorak\n");
	for(int i= 0; i < len; i++)
	{
		char letter = string[i];
		switch(letter)
		{
			case 'a':
				printf("%c",'a');
				break;
			case 'b':
                                printf("%c",'x');
				break;
			case 'c':
                                printf("%c",'j');
				break;
 			case 'd':
                                printf("%c",'e');
                                break;
                        case 'e':
                                printf("%c",'.');
                                break;
                        case 'f':
                                printf("%c",'u');
                                break;
                        case 'g':
                                printf("%c",'i');
                                break;
                        case 'h':
                                printf("%c",'d');
                                break;
                        case 'i':
                                printf("%c",'c');
                                break;
                        case 'j':
                                printf("%c",'h');
                                break;
                        case 'k':
                                printf("%c",'t');
                                break;
                        case 'l':
                                printf("%c",'n');
                                break;
                        case 'm':
                                printf("%c",'m');
                                break;
                        case 'n':
                                printf("%c",'b');
                                break;
                        case 'o':
                                printf("%c",'r');
                                break;
                        case 'p':
                                printf("%c",'l');
                                break;
                        case 'q':
                                printf("%c",'\'');
                                break;
                        case 'r':
                                printf("%c",'p');
                                break;
                        case 's':
                                printf("%c",'o');
                                break;
                        case 't':
                                printf("%c",'y');
                                break;
                        case 'u':
                                printf("%c",'g');
                                break;
                        case 'v':
                                printf("%c",'k');
                                break;
                        case 'w':
                                printf("%c",',');
                                break;
                        case 'x':
                                printf("%c",'q');
                                break;
                        case 'y':
                                printf("%c",'f');
                                break;
                        case 'z':
                                printf("%c",';');
                                break;
                        case 'A':
                                printf("%c",'A');
                                break;
                        case 'B':
                                printf("%c",'X');
                                break;
                        case 'C':
                                printf("%c",'J');
                                break;
                        case 'D':
                                printf("%c",'E');
                                break;
                        case 'E':
                                printf("%c",'>');
                                break;
                        case 'F':
                                printf("%c",'U');
                                break;
                        case 'G':
                                printf("%c",'I');
                                break;
                        case 'H':
                                printf("%c",'D');
                                break;
                        case 'I':
                                printf("%c",'C');
                                break;
                        case 'J':
                                printf("%c",'H');
                                break;
                        case 'K':
                                printf("%c",'T');
                                break;
                        case 'L':
                                printf("%c",'N');
                                break;
                        case 'M':
                                printf("%c",'M');
                                break;
                        case 'N':
                                printf("%c",'B');
                                break;
                        case 'O':
                                printf("%c",'R');
                                break;
                        case 'P':
                                printf("%c",'L');
                                break;
                        case 'Q':
                                printf("%c",'"');
                                break;
                        case 'R':
                                printf("%c",'P');
                                break;
                        case 'S':
                                printf("%c",'O');
                                break;
                        case 'T':
                                printf("%c",'Y');
                                break;
                        case 'U':
                                printf("%c",'G');
                                break;
                        case 'V':
                                printf("%c",'K');
                                break;
                        case 'W':
                                printf("%c",'<');
                                break;
                        case 'X':
                                printf("%c",'Q');
                                break;
                        case 'Y':
                                printf("%c",'F');
                                break;
                        case 'Z':
                                printf("%c", ':');
                                break;
			default:
				break;
		}
	}
}
