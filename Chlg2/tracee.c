#include <stdio.h>
#include <unistd.h>

int foo(int i)

{
	printf("foo is doing some things : \n");	
	sleep(5);
	return i;
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
	}
	return 0;
}
