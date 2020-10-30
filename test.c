#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
int main()
{  
     char text[100];
    printf("Invoking 'listProcessInfo' system call");
    int fd = open("./aqui.txt", O_WRONLY|O_CREAT, 0666);
     printf("Digite um texto [max. 100 carac.]: ");
	scanf("%[^\n]", text);

    long int ret_status = syscall(333,fd,text,strlen(text)); 
    close(fd);
    fd = open("./aqui.txt", O_RDONLY|O_CREAT, 0666);
    char rec[100];
    long int ret_status2 = syscall(334,fd,rec,strlen(text));
    printf("%s",rec);
         
    if(ret_status >= 0) 
         printf("System call 'write_crypt' executed correctly. Use dmesg to check processInfo\n");
    
    else 
         printf("System call 'write_crypt' did not execute as expected\n");

    if(ret_status2 >= 0) 
         printf("System call 'read_crypt' executed correctly. Use dmesg to check processInfo\n");
    
    else 
         printf("System call 'read_crypt' did not execute as expected\n");
          
          
     return 0;
}
