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

	// We are looking at the output of the previous pgrep
	// If the pgrep suceed we should have the pid in the standard input
	// Else the pgrep or the fscanf failed
	
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

	// We have asked to be attached to the tracee, we have to wait for him to respond
	
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

	// The binary file have the format addr type name and sometimes the addr is missing
	// the  "while(fgetc(nm) != '0') ;" allow us to skip those lines
	
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
	int trap = 0xcc;
	fseek(mem,addr,1); // We set our head at foo's addr to write the trap in it code
	fwrite(&trap, 1, 1, mem); 
	printf("foo is trapped\n");
	fclose(mem);

	// The CONT is there to allow the tracee to continue his excecution
	
	ptrace(PTRACE_CONT, pid, NULL, NULL) ;
	ptrace(PTRACE_DETACH, pid,NULL, NULL) ;
	
	return 0;

Exit:
	return 1;
}

