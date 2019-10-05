#include <sys/ptrace.h>
#include <unistd.h>
#include <stdio.h>

#define ERROR(msg) { fprintf(msg, stderr); goto Exit; }

int main (int argc, char** argv)
{
	// Getting the pid of the tracee process
	
	printf("Finf the pid of the tracee programm\n");

	if( execl("/bin/pgrep", "tracee",NULL) < 0)
	     ERROR("Unable to pgrep tracee\n")

	pid_t pid;
	if(fread(&pid,sizeof(pid_t),1,stdout) < 0)
	     ERROR("Unable to read PID in stdout\n")

	printf("Pid find it's : %d\n", pid);

	// Attaching to the tracee process

	printf("Ask for attaching\n");
	
	if(ptrace(PTRACE_ATTACH, pid,NULL, NULL) < 0)
	     ERROR("Could not trace PID\n")

	if(waitpid(pid, NULL, 0) < 0)
	     ERROR("Error while waiting for PID\n")
	
	printf("Attached\n");

	// Looking for foo in the tracee binary
	
	printf("Looking for foo's addr\n");
	if( execl("/bin/nm", "tracee",NULL) < 0)
	     ERROR("Could not exec nm on tracee\n")

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

	printf("foo addr is : %d\n", addr);


Exit:
	return 0;
}
