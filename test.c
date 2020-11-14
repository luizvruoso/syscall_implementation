#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
int main()
{  
     char text[256] = {0};
    printf("Invoking 'listProcessInfo' system call");
    int fd = open("./data.txt", O_WRONLY|O_CREAT, 0666);
     printf("Digite um texto [max. 256 carac.]: \n");
	scanf("%[^\n]", text);

    long int ret_status = syscall(333,fd,text,strlen(text)); 
    close(fd);
    fd = open("./data.txt", O_RDONLY|O_CREAT, 0666);
    char rec[256] = {0};
    long int ret_status2 = syscall(334,fd,rec,strlen(text));
    printf("Texto Descriptografado: %s \n",rec);
         
    if(ret_status >= 0) 
         printf("\nSystem call 'write_crypt' executed correctly. Use dmesg to check processInfo\n");
    
    else 
         printf("\nSystem call 'write_crypt' did not execute as expected\n");

    if(ret_status2 >= 0) 
         printf("\nSystem call 'read_crypt' executed correctly. Use dmesg to check processInfo\n");
   
    else 
        printf("\nSystem call 'read_crypt' did not execute as expected\n");
          
          
     return 0;
}
