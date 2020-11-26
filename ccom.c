/*
Gabriel Gonçalves Mattos Santini -  18189084
Luiz Vinicius dos Santos Ruoso - 18233486
Marcelo Germani Olmos -  18048298    
Victor Felipe dos Santos -  18117820
Victor Luiz Fraga Soldera - 18045674
*/

#include<linux/kernel.h>
#include<linux/init.h>
#include<linux/sched.h>
#include<linux/syscalls.h>
#include <linux/unistd.h>
#include "com.h"

#define KEY  "0123456789ACBDEF"

asmlinkage ssize_t write_crypt(int fd, const void*buf, size_t nbytes){
    encrypt(buf, strlen(buf), KEY); //a funcao edita na raiz do buf, ou seja no need of returns
    return sys_write(fd,buf,256);
}

asmlinkage ssize_t read_crypt(int fd, void*buf, size_t nbytes){
    ssize_t ctrl = sys_read(fd,buf,256);

    if(ctrl >= 0){
        decrypt(buf, strlen(buf), KEY); //a funcao edita na raiz do buf, ou seja no need of returns
    }

    return ctrl;
}
