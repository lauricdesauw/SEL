#include <sys/ptrace.h>
#include <unistd.h>
#include <stdio.h>

int main (int argc, char** argv)
{
	// Getting the pid of the tracee process

	if( execl("/bin/pgrep", "tracee",NULL) < 0)
	{}

	pid_t pid;
	if(fread(&pid,sizeof(pid_t),1,stdout) < 0)
	{}

	// Attaching to the tracee process

	if(ptrace(PTRACE_ATTACH, pid,NULL, NULL) < 0)
	{}

	if(waitpid(pid, NULL, 0) < 0)
	{}

	// Looking for foo in the tracee binary
	if( execl("/bin/nm", "tracee",NULL) < 0)
	{}

	int addr;
	char type;
	char name[1000];
	while(1)
	{
		fscanf(stdout, "%x %c %s", &addr, &type, name);
		if(!addr)
			continue;

		if(type == 'T')
		{
			if(name[0] == 'f')

			{
				if(name[1] == 'o')

				{
					if(name[2] == 'o')

					{
						if(name[3] == '\0')
						{
							break;
						}
					}
				}
			}
		}
	}



	return 0;
}
