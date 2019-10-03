void volatile foo()
{
	static int i; 
	++i;
}


int main(int argc, char** argv)
{ 
	while(1)
	{
		foo();
	}
	return 0;
}
