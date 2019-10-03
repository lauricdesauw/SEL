#include <sys/ptrace.h>
#include <unistd.h>
#include <stdio.h>

int main (int argc, char** argv)
{
	// Getting the pid of the tracee process

	int err = execl("/bin/pgrep", "tracee",NULL);		
	pid_t pid;
	fread(&pid,sizeof(pid_t),1,stdout);	
	
	// Attaching to the tracee process

	ptrace(PTRACE_ATTACH, pid,NULL, NULL); 
	waitpid(pid, NULL, 0);

	// Looking for foo in the tracee binary

	


}
