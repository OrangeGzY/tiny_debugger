#include <stdio.h>

int func1()
{
    printf("function1");
}

void func2()
{
    printf("function2");
}

void func3()
{
    printf("fucntion3");
}

int main()
{
    //printf("===========\n");
    func1();
    func3();
    func2();
    func2();
    func3();
    //printf("===========\n");
    return 0;
}    