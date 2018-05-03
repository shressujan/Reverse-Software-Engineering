//
//  main.c
//  lab4
//
//  Created by Sujan Shrestha on 2/20/18.
//  Copyright © 2018 Sujan Shrestha. All rights reserved.
//
#include<stdlib.h>
#include<string.h>
#include<stdio.h>
#include<math.h>

//typedef struct with 3 fields
typedef struct data
{
    char offset[10];
    char hex [41];
    char ascii [17];
}data;

int main(int argc, char ** argv)
{
    FILE *fptr;
    FILE *fptr2 = fopen( argv[1],"w");
    // Program exits if the file pointer returns NULL.
    fptr = fopen("hello.txt", "r");
    if(fptr == NULL){
        printf("Error! opening file");
    }
    // Moves the cursor to the end of the file
    fseek(fptr,0L, SEEK_END);
    int size = (int)ftell(fptr);
    int lines =(int) ceil(size/68.0);

    //Allocating space for input
    data * input;
    input = malloc (sizeof(data) * lines);

    fseek(fptr,0L, SEEK_SET);
    //read the file contents into input
    fread(input, sizeof(data), lines, fptr);
    for(int i =0; i < lines; i++)
    {
        for(int j=0; j < 10; j++)
        {
            fprintf (fptr2, "%c", input[i].offset[j]);
        }
        fprintf (fptr2, "%c", ' ');
        for(int k= 0; k < 41; k++)
        {
            if(input[i].hex[k] != ' ')
            {
                printf("0x");
                printf("%c", input[i].hex[k]);
                fprintf (fptr2, "%c", input[i].hex[k]);
                printf("%c ", input[i].hex[++k]);
                fprintf (fptr2, "%c", input[i].hex[k]);
            }
            else
            {
                 printf("%c", input[i].hex[k]);
                 fprintf (fptr2, "%c", input[i].hex[k]);
            }
        }
         fprintf (fptr2, "%c", ' ');
        for(int l = 0; l< 17; l++)
        {
            fprintf (fptr2, "%c", input[i].ascii[l]);
        }
	printf("\n");
    }
    fclose(fptr);
    return 0;
}

