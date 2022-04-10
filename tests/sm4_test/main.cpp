#include <stdio.h>
#include <stdlib.h>
#include <ezcrypto.h>
#include <sm4.h>
int main(int argc, char** argv)
{
    ezcrypto::sm4::ecb(true, nullptr, 0);
    return 0;
}