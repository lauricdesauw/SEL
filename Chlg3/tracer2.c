#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/mman.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#define ERROR_ERRNO(msg) { fprintf(stderr, msg, strerror(errno)); goto Exit; }
#define ERROR(msg) { fprintf(stderr, msg); goto Exit; }

typedef struct user_regs_struct user_regs_struct;

pid_t trace(const char* tracee, const int n)
{
     char* pgrep_s = malloc((n+6) * sizeof(char));

     if(pgrep_s == NULL)
	  goto Exit;
     
     strcpy(pgrep_s, "pgrep ");
     strncat(pgrep_s, tracee, n);
     
     printf("Looking for the pid of the tracee program\n");

     // Usign pgrep to get the pid of the program to trace
     
     pid_t pid;
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

     free(pgrep_s);
     
     return pid;
     
Exit:
     free(pgrep_s);

     return -1;
}

int get_addr(const char* path, const int p, const char* fs[],
	     const int n, unsigned long long addr[])
{
     char* nm_s = malloc((p+3) * sizeof(char));

     strcpy(nm_s, "nm ");
     strncat(nm_s, path, p);

     // Using nm to get the adresses of the functions we're interested in
     
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
	  // Reading nm output
	  
	  while(fgetc(nm) != '0') ;
	  if(fscanf(nm,"%x %c %s", &addr_tmp, &type, name) == EOF)
	  {
	       ERROR_ERRNO("Error while reading nm output ! %s\n")
	  }

	  // Check if the name is one of the functions we're looking for
	  for(i = 0; i < n; ++i)
	  {
	       if(!strcmp(name, fs[i]))
	       {
		    addr[i] = addr_tmp;
		    ++found;
		    break;
	       }
	  }

	  // Once they've all been found, we can leave
	  if(found == n)
	       break;
     }
     
     pclose(nm);

     return 0;
     
Exit:
     return -1;
}

int write_to_mem(const pid_t pid, const char* to_write, const int n,
		  const unsigned long long addr, char* save_buffer)
{
     // Open the memory of the tracee
     
     char path[25] = {0};
     sprintf(path, "/proc/%d/mem", pid); 

     FILE* mem = fopen(path, "r+");

     if(mem == NULL)
     {
	  ERROR_ERRNO("Could not open mem %s\n");
     }

     printf("Seeking...\n");

     // Find the right spot...
     
     if(fseek(mem, addr, SEEK_SET) < 0)
     {
	  ERROR_ERRNO("Could not fseek address ! %s\n");
     }

     // ...if we care about it, remember it...
     
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

     // ...and overwrite it
     
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

int set_and_save_regs(const pid_t pid, const user_regs_struct* curr_reg,
		      unsigned long long *regs_to_change[],
		      unsigned long long values[], const int size)
{
     printf("Saving registers...\n");

     // Setting the values and remembering the original ones
     
     unsigned long long tmp;
     for(int i = 0; i < size; i++)
     {
	  tmp = *regs_to_change[i];
	  *regs_to_change[i] = values[i];
	  values[i] = tmp;
     }

     // Actually setting the registers 
     printf("Setting registers...\n");
     
     if(ptrace(PTRACE_SETREGS, pid, NULL, curr_reg) < 0)
     {
	  ERROR_ERRNO("Could not modify registers ! %s\n");
     }
  
     return 0;

Exit:
     return -1; 
}

int get_path_libc(const pid_t pid, char name[], unsigned long long* offset)
{
     // Read maps to find where the libc is as well as its offset
     char cat_s[35];
     sprintf(cat_s, "cat /proc/%d/maps | grep libc", pid);

     FILE* cat = popen(cat_s, "r");
     unsigned long long o[5];
     char c[2], type[5];

     while(1)
     {
	  if(fscanf(cat, "%llx %c %llx %s %llx %llx %c %llx %llx %s",
		    offset, c, o, type, o+1, o+2, c+1, o+3, o+4, name) == EOF)
	  {
	       ERROR_ERRNO("Could not read cat | grep ! %s")
	  };

	  printf("%s\n", name);

	  // If it's executable, it's the right one
	  if(!strcmp(type, "r-xp"))
	       break;
     }

     return 0;
     
Exit:
     return -1;
}

int get_libc_addr(const pid_t pid, const char* fs[], const int n, unsigned long long addr[])
{
     // Wrapper for getting the libc and getting the addresses of functions inside it
     char path[1000];
     unsigned long long offset;

     if(get_path_libc(pid, path, &offset) < 0)
     {
	  ERROR("Could not find libc path !\n")
     }

     printf("%s %lu\n", path, strlen(path));
     
     if(get_addr(path, strlen(path), fs, n, addr) < 0)
     {
	  ERROR("Could not find functions in libc !\n")
     }

     for(int i = 0; i < n; ++i)
	  addr[i] += offset;

     return 0;
     
Exit:
     return -1;
}

void print_maps(pid_t pid)
{
     char path[25];
     sprintf(path, "/proc/%d/maps", pid);

     FILE* f = fopen(path, "r");
     char c;

     do
     {
	  c = fgetc(f);

	  if(c == EOF)
	       break;

	  printf("%c", c);
     } while(1);
}

int main (int argc, char** argv)
{
     // Getting the pid of the tracee process
     pid_t pid = trace("tracee", 7);
     size_t code_size = 1000;

     if(pid < 0)
	  goto Exit;

     print_maps(pid);
     
     // Looking for the libc and foo addr

     printf("Looking for libs's functions' addr\n");
     
     const char* fs[3] = {"foo", "posix_memalign","mprotect"};
     unsigned long long addr[3];
     
     if(get_addr("tracee", 7, fs, 1, addr) < 0)
	  goto Exit;

     if(get_libc_addr(pid, fs + 1, 2, addr + 1) < 0)
	  goto Exit;
     
     unsigned long long addr_memalign = addr[1], addr_mprotect = addr[2], addr_foo = addr[0];
     printf("%llx %llx\n", addr_memalign, addr_mprotect);
     
     // Write the code in the tracee

     char foo_code[7];
     char call_trap[7] = {0xcc, 0xff, 0xd0, 0xcc , 0xff, 0xd0, 0xcc};

     if(write_to_mem(pid, call_trap, 7, addr_foo, foo_code) < 0)
	  goto Exit;
     
     ptrace(PTRACE_CONT, pid, NULL, NULL) ;
     
     // getting the values in the registers

     if(waitpid(pid, NULL, 0) < 0)
     {
	  ERROR("Error while waiting for PID\n");
     }
     
     user_regs_struct regs, rem_regs;	

     if(ptrace(PTRACE_GETREGS, pid, NULL, &regs) < 0)
     {
	  ERROR_ERRNO("Error while getting registers ! %s\n")
     }

     rem_regs = regs;

     // Updating registers to call posix_memalign correctly

     unsigned long long* regs_addr[5] = {&regs.rax, &regs.rdi, &regs.rsi, &regs.rdx, &regs.rsp};
     unsigned long long values[5] = {addr_memalign, regs.rsp,
				     getpagesize(), code_size, regs.rsp - sizeof(void*)};

     printf("Writing call to posix_memalign...\n");
     
     if(set_and_save_regs(pid, &regs, regs_addr, values, 5) < 0)
	  goto Exit;

     printf("Waiting for tracee to call posix_memalign...\n");
     
     ptrace(PTRACE_CONT, pid, NULL, NULL) ;

     if(waitpid(pid, NULL, 0) < 0)
     {
	  ERROR("Error while waiting for PID\n");
     }

     user_regs_struct tmp_regs;

     if(ptrace(PTRACE_GETREGS, pid, NULL, &tmp_regs) < 0)
     {
	  ERROR_ERRNO("Error while getting registers ! %s\n")
     }

     // Checking the return value of posix_memalign
     printf("%llx \n", tmp_regs.rax);
     
     if(tmp_regs.rax < 0)
     {
	  printf("Error while calling posix_memalign !\n");
	  
	  if(tmp_regs.rax == EINVAL)
	       printf("Invalid alignment !\n");
	  else
	       printf("Not enough memory !\n");
     }

     // Changing registers to correctly call mprotect
     unsigned long long tmp_values[4] = {addr_mprotect, (unsigned long long)
					 regs.rdi, code_size,
					 PROT_EXEC | PROT_READ};

     printf("Writing call to mprotect...\n");

     if(set_and_save_regs(pid, &tmp_regs, regs_addr, tmp_values, 4) < 0)
	  goto Exit;
     
     printf("Waiting for tracee to call mprotect...\n");
     
     ptrace(PTRACE_CONT, pid, NULL, NULL) ;

     if(waitpid(pid, NULL, 0) < 0)
     {
	  ERROR("Error while waiting for PID\n");
     }
     
     if(ptrace(PTRACE_GETREGS, pid, NULL, &tmp_regs) < 0)
     {
	  ERROR_ERRNO("Error while getting registers ! %s\n")
     }

     // Checking mprotect return value
     printf("%llx \n", tmp_regs.rax);
     
     if(tmp_regs.rax < 0)
     {
	  ERROR_ERRNO("Error while calling mprotect ! %s\n")
     }
     
     printf("Restoring registers...\n");

     // Restoring registers to their initial values
     if(ptrace(PTRACE_SETREGS, pid, NULL, &rem_regs) < 0)
     {
	  ERROR_ERRNO("Could not restore registers ! %s\n")
     }

     printf("Registers are restored\n");

     printf("Restoring code...\n");
     
     if(write_to_mem(pid, foo_code, 7, addr_foo, NULL) < 0)
	  goto Exit;
     
     printf("foo is restored\n");

     print_maps(pid);
     
     ptrace(PTRACE_CONT, pid, NULL, NULL);
     ptrace(PTRACE_DETACH, pid, NULL, NULL);

     return 0;

Exit:
     return 1;
}




