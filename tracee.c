#include <stdio.h>

void volatile foo()

{
	static int i; 
	++i;
	printf("foo executed %d\n", i);
}


int main(int argc, char** argv)
{ 
	
	while(1)
	{
		printf("I'm totally foo\n");
		foo();
	}
	return 0;
}
