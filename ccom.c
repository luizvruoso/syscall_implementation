#include<linux/kernel.h>
#include<linux/init.h>
#include<linux/sched.h>
#include<linux/syscalls.h>
#include <linux/unistd.h>
#include "com.h"

#define KEY  "0123456789ACBDEF"

asmlinkage ssize_t write_crypt(int fd, const void*buf, size_t nbytes){
    encrypt(buf, strlen(buf), KEY); //a funcao edita na raiz do buf, ou seja no need of returns
    return sys_write(fd,buf,16);
}

asmlinkage ssize_t read_crypt(int fd, void*buf, size_t nbytes){
    ssize_t ctrl = sys_read(fd,buf,16);

    if(ctrl >= 0){
        decrypt(buf, strlen(buf), KEY); //a funcao edita na raiz do buf, ou seja no need of returns
    }

    return ctrl;
}