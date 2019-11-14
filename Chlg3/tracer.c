#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>

#define ERROR_ERRNO(msg) { fprintf(stderr, msg, strerror(errno)); goto Exit; }
#define ERROR(msg) { fprintf(stderr, msg); goto Exit; }

typedef struct user_regs_struct user_regs_struct;

pid_t trace(const char* tracee)
{
     // Getting the pid of the tracee process

     printf("Looking for the pid of the tracee program\n");

     pid_t pid;
     
     FILE* pgrep = popen("pgrep", "r");

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
}

int main (int argc, char** argv)
{
     
     // Looking for foo in the tracee binary

     printf("Looking for foo's addr\n");

     FILE* nm = popen("nm tracee", "r");
     int addr;
     int addr_foo = 0;
     int addr_goo = 0;
     char type;
     char name[1000];

     while(1) 
     {
	  while(fgetc(nm) != '0') ;
	  fscanf(nm,"%x %c %s",&addr,&type ,name);

	  if(!strcmp(name, "foo"))
	       addr_foo = addr;

	  if(!strcmp(name, "goo"))
	       addr_goo = addr;

	  if(addr_foo && addr_goo) 
	       break;
     }
     pclose(nm);
     printf("foo addr is : %x\n", addr_foo);
     printf("goo addr is : %x\n", addr_goo);

     char path[25] = {0};
     sprintf(path, "/proc/%d/mem", pid); 

     FILE* mem = fopen(path, "r+");

     if(mem == NULL)
     {
	  ERROR_ERRNO("Could not open mem %s\n");
     }
     int trap = 0xcc;
     unsigned long long int goo_code;
     // Save goo code 
     fseek(mem,addr_goo, SEEK_SET);
     fread(&goo_code, 4, 1, mem); 
     
     // Trap goo 
     fseek(mem,addr_goo, SEEK_SET);
     fwrite(&trap, 1, 1, mem);
     printf("goo is trapped\n");
     fclose(mem);

     ptrace(PTRACE_CONT, pid, NULL, NULL) ;

     // getting the value in the register 

     if(waitpid(pid, NULL, 0) < 0)
     {
	  ERROR("Error while waiting for PID\n");
     }
     
     user_regs_struct regs;	

     ptrace(PTRACE_GETREGS, pid, NULL, &regs);

     // Change the goo code to call foo with parameter
     
     unsigned long long rax = regs.rax, rdi = regs.rdi;
     regs.rax = addr_foo;
     regs.rdi = 5;

     char call_trap[] = {0xff, 0xd0, 0xcc};

     mem = fopen(path, "r+");

     if(mem == NULL)
     {
	  ERROR_ERRNO("Could not open mem %s\n");
     }
     fseek(mem, addr_goo + 1, SEEK_SET);
     fwrite(call_trap, 1, 3, mem);
     fclose(mem);
     
     ptrace(PTRACE_SETREGS, pid, NULL, &regs);
     ptrace(PTRACE_CONT, pid, NULL, NULL) ;

     if(waitpid(pid, NULL, 0) < 0)
     {
	  ERROR("Error while waiting for PID\n");
     }
     
     // Restore the goo code and register value
     regs.rax = rax;
     regs.rdi = rdi;
     regs.rip = addr_goo;
     ptrace(PTRACE_SETREGS, pid,NULL , &regs);
     printf("Register are restored\n");

     mem = fopen(path, "r+");
     if(mem == NULL)
     {
	  ERROR_ERRNO("Could not open mem %s\n");
     }
     fseek(mem,addr_goo,1);
     fwrite(&goo_code, 4, 1, mem);
     printf("goo is restored\n");
     fclose(mem);


     ptrace(PTRACE_CONT, pid, NULL, NULL) ;
     ptrace(PTRACE_DETACH, pid,NULL, NULL) ;


     return 0;

Exit:
     return 1;
}



