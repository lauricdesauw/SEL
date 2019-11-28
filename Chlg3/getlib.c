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

int get_path_libc(const pid_t pid, char** name)
{

  char path[25] = {0};
  sprintf(path, "/proc/%d/maps", pid); 
  int p =25;
  
  char* cat_s = malloc(3* sizeof(char));

  strcpy(cat_s, "cat ");
  strncat(cat_s, path, p);
     
  FILE* cat = popen(cat_s, "r");
  char type[5];
  char name_tmp[1000];
  int addr_tmp = 0, garbage;

  if(cat == NULL)
    {
      ERROR_ERRNO("Could not cat ! %s\n")
	}
     
  while(1) 
    {
	 printf("1\n");
      while(fgetc(cat)) ;
      if(fscanf(cat,"%x %x %s %x %x %x %x %s", &addr_tmp, &garbage, type,
		&garbage, &garbage, &garbage, &garbage,
		name_tmp) == EOF)
	{
	  ERROR_ERRNO("Error while reading nm output ! %s\n")
	    }


      if(!strcmp(type, "r-xp") && !strcmp(name_tmp, "/lib/x86_64-linux-gnu/libc-2.27.so"))
	{
	  name[0] = name_tmp;
	  break;
	}

    }
     
  pclose(cat);

  return 0;
     
 Exit:
  return -1;
}


int get_offset(const pid_t pid, const char* fs[], const int n, int addr[])
{
  char* path;
  if (get_path_libc(pid ,&path) < 0)
    {
      ERROR("Error finding the name of the libc");
    }

  if(get_addr(path, 21, fs, n, addr) < 0 )
    {
      ERROR("Error finding the functions in the libc");
    }
  
  return 0;
    
 Exit :
  return -1;
}
