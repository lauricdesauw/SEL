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

	char addr[16];
	char type[1];
	char* name;
	int part = 0;

		
	


	// Finding the call to foo

	// Writing our function

	// Replacing foo by our function
	return 0;
}
