#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#define ERROR_ERRNO(msg) { fprintf(stderr, msg, strerror(errno)); goto Exit; }
#define ERROR(msg) { fprintf(stderr, msg); goto Exit; }

typedef struct user_regs_struct user_regs_struct;

pid_t trace(const char* tracee, const int n) // Function to attach our processus to another one with the name tracee. n is the size of that name.
{
     char* pgrep_s = malloc((n+6) * sizeof(char));

     if(pgrep_s == NULL)
	  goto Exit;
     
     strcpy(pgrep_s, "pgrep ");
     strncat(pgrep_s, tracee, n);
     
     printf("Looking for the pid of the tracee program\n");

     pid_t pid;

     // Getting the pid of the tracee process
     
     FILE* pgrep = popen(pgrep_s, "r");

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

     return pid;
     
Exit:
     free(pgrep_s);

     return -1;
}

int get_addr(const char* path, const int p, const char* fs[], const int n, int addr[]) // Search the n function of fs in the path and if there is put the corresponding addresses in addr. p is the size of the path.
{
     char* nm_s = malloc((n+3) * sizeof(char));

     strcpy(nm_s, "nm ");
     strncat(nm_s, path, p);
     
     FILE* nm = popen(nm_s, "r");
     char type;
     char name[1000];
     int i, addr_tmp, found = 0;

     if(nm == NULL)
     {
	  ERROR_ERRNO("Could not nm ! %s\n")
     }
     
     while(1) 
     {
	  while(fgetc(nm) != '0') ;
	  if(fscanf(nm,"%x %c %s", &addr_tmp, &type, name) == EOF)
	  {
	       ERROR_ERRNO("Error while reading nm output ! %s\n")
	  }

	  for(i = 0; i < n; ++i)
	  {
	       if(!strcmp(name, fs[i]))
	       {
		    addr[i] = addr_tmp;
		    ++found;
		    break;
	       }
	  }
	  
	  if(found == n)
	       break;
     }
     
     pclose(nm);

     return 0;
     
Exit:
     return -1;
}

int write_to_mem(const pid_t pid, const char* to_write, const int n,
		 const unsigned long long addr, char* save_buffer) // Write the buffer to_write in the mem of the process and save the mem in save_buffer 
{
     char path[25] = {0};
     sprintf(path, "/proc/%d/mem", pid); 

     FILE* mem = fopen(path, "r+");

     if(mem == NULL)
     {
	  ERROR_ERRNO("Could not open mem %s\n");
     }

     printf("Seeking...\n");

     if(fseek(mem, addr, SEEK_SET) < 0)
     {
	  ERROR_ERRNO("Could not fseek address ! %s\n");
     }

     if(save_buffer != NULL)
     {
	  printf("Saving...\n");
	  if(!fread(save_buffer, 1, n, mem))
	  {
	       ERROR_ERRNO("Error while reading memory ! %s\n");
	  }

	  if(fseek(mem, addr, SEEK_SET) < 0)
	  {
	       ERROR_ERRNO("Could not fseek address ! %s\n");
	  }
     }

     printf("Writing...\n");

     if(!fwrite(to_write, 1, n, mem))
     {
	  ERROR_ERRNO("Error while writing in memory ! %s\n");
     }

     printf("Code succesfully modified\n");
     fclose(mem);

     return 0;
     
Exit:
     fclose(mem);
     
     return -1;
}

int main (int argc, char** argv)
{
     // Getting the pid of the tracee process

     pid_t pid = trace("tracee", 7);

     if(pid < 0)
	  goto Exit;
     
     // Looking for goo and bar in the tracee binary

     const char* fs[2] = {"goo", "bar"};
     int addr[2];
     
     if(get_addr("tracee", 7, fs, 2, addr) < 0)
	  goto Exit;

     unsigned long long addr_goo = addr[0], addr_bar = addr[1];
     
     printf("Looking for bar's addr\n");

     char goo_code[4];
     char call_trap[] = {0xcc, 0xff, 0xd0, 0xcc};

     if(write_to_mem(pid, call_trap, 4, addr_goo, goo_code) < 0)
	  goto Exit;

     ptrace(PTRACE_CONT, pid, NULL, NULL) ;

     // getting the values in the registers

     if(waitpid(pid, NULL, 0) < 0)
     {
	  ERROR("Error while waiting for PID\n");
     }
     
     user_regs_struct regs;	

     if(ptrace(PTRACE_GETREGS, pid, NULL, &regs) < 0)
     {
	  ERROR_ERRNO("Error while getting registers ! %s\n")
     }
    
     // Change the goo code to call bar with parameter

     printf("Saving registers...\n");
     unsigned long long rax = regs.rax, rdi = regs.rdi, rsp = regs.rsp, rip = regs.rip;
     regs.rax = addr_bar;
     regs.rsp -= 1; // We are increasing the stack pointer in order to make an allocation in the stack 
     regs.rdi = regs.rsp + 1; // The argument we give to tghe function is a pointer on the space just allocated in the stack

     printf("Writing value...");
     char value = 7;

     if(write_to_mem(pid, &value, 1, regs.rdi, NULL) < 0) // We are writting the value in the stack, at the end of the previous pointer
       goto Exit;                                         // We have took the value 7 to see if our code work and do not print something randomly in the memory


     printf("Setting registers...\n");
     if(ptrace(PTRACE_SETREGS, pid, NULL, &regs) < 0)
     {
	  ERROR_ERRNO("Could not modify registers ! %s\n");
     }
     
     ptrace(PTRACE_CONT, pid, NULL, NULL) ;

     if(waitpid(pid, NULL, 0) < 0)
     {
	  ERROR("Error while waiting for PID\n");
     }
     
     // Restore the goo code and register value
     printf("Restoring registers...\n");
     regs.rax = rax;
     regs.rdi = rdi;
     regs.rsp = rsp;
     regs.rip = rip;

     if(ptrace(PTRACE_SETREGS, pid, NULL, &regs) < 0)
     {
	  ERROR_ERRNO("Could not restore registers ! %s\n");
     }
     printf("Registers are restored\n");

     printf("Restoring code...\n");
     
     if(write_to_mem(pid, goo_code, 4, addr_goo, NULL) < 0)
	  goto Exit;
     
     printf("goo is restored\n");

     ptrace(PTRACE_CONT, pid, NULL, NULL);
     ptrace(PTRACE_DETACH, pid, NULL, NULL);

     return 0;

Exit:
     return 1;
}



