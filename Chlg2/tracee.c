#include <stdio.h>
#include <unistd.h>

int foo(int i)

{
     printf("foo is doing some things : %d\n", i);	
     sleep(5);
     return i;
}

int bar(int* i)
{
     char* c = (char *) i;
     printf("bar is doing stuff : %d\n", *c);
     sleep(5);
     return 5;
}

void goo()
{ 
		sleep(1);
		printf("Evrything is normal\n");	
} 

int main(int argc, char** argv)
{ 
	while(1)
	{
	  goo();
	}
	return 0;
}
