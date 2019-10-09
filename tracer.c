#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>

#define ERROR_ERRNO(msg) { fprintf(stderr, msg, strerror(errno)); goto Exit; }
#define ERROR(msg) { fprintf(stderr, msg); goto Exit; }

int main (int argc, char** argv)
{
	// Getting the pid of the tracee process

	printf("Looking for the pid of the tracee program\n");

	pid_t pid;
	FILE* pgrep = popen("pgrep tracee", "r");

	if(fscanf(pgrep, "%d", &pid) == EOF)
	{
		ERROR_ERRNO("Unable to get PID ! %s\n");
	}

	pclose(pgrep);

	printf("Pid found, it's : %d\n", pid);

	// Attaching to the tracee process

	printf("Ptracing...\n");

	if(ptrace(PTRACE_ATTACH, pid,NULL, NULL) < 0)
	{
		ERROR_ERRNO("Could not trace PID ! %s\n");
	}

	if(waitpid(pid, NULL, 0) < 0)
	{
		ERROR("Error while waiting for PID\n");
	}

	printf("Attached\n");

	// Looking for foo in the tracee binary

	printf("Looking for foo's addr\n");

	FILE* nm = popen("nm tracee", "r");
	int addr;
	char type;
	char name[1000];

	while(1) 
	{
		while(fgetc(nm) != '0') ;
		fscanf(nm,"%x %c %s",&addr,&type ,name);

		if(!strcmp(name, "foo"))
			break;
	}
	pclose(nm);
	printf("foo addr is : %x\n", addr);

	char path[25] = {0};
	sprintf(path, "/proc/%d/mem", pid); 

	FILE* mem = fopen(path, "r+");

	if(mem == NULL)
	{
		ERROR_ERRNO("Could not open mem %s\n");
	}

	char c = fgetc(mem);
	if(c==EOF)
		ERROR_ERRNO("EOF %s\n");

	while(c != EOF)
	{
		printf("%c", c);
		c = fgetc(mem);
	}

	return 0;

Exit:
	return 1;
}
