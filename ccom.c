#include<linux/kernel.h>
#include<linux/init.h>
#include<linux/sched.h>
#include<linux/syscalls.h>
#include <linux/unistd.h>
#include "com.h"

asmlinkage ssize_t write_crypt(int fd, const void*buf, size_t nbytes){
    return write(fd,buf,nbytes);
}

asmlinkage ssize_t read_crypt(int fd, void*buf, size_t nbytes){
    return read(fd,buf,nbytes);
}