#include "pincrack.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int isRoot()
{
    if (getuid() != 0)
    {
        return 0;
    }
    else
    {
        return 1;
    }
}

int main(int argc, char *argv[])
{

    int pin = 0;

    if (argc != 2)
    {
        printf("Usage: pincracktest <SHA-1 hash of 4 digit PIN>\n");
        exit(-1);
    }
    if (!isRoot())
    {
        printf("This program must be run as root/sudo user!!");
        exit(0);
    }

    pin = pincrack(argv[1], strlen(argv[1]));

    if (pin != -1)
        printf("PIN found: %d\n", pin);
    else
        printf("PIN could not be found\n");
}
