#!/bin/bash

echo "Copiando com.h e ccom.c para linux-source -----------"

sudo mkdir -p /usr/src/linux-source-4.15.0/info
sudo cp ./com.h /usr/src/linux-source-4.15.0/info

echo "obj-y:=ccom.o">Makefile

echo "É necessário agora editar alguns arquivos--------"
echo "Primeiro, editar Makefile do kernel"
echo "Garanta que na linha 882, haja seu /info "

sudo gedit /usr/src/linux-source-4.15.0/Makefile
sudo gedit /usr/src/linux-source-4.15.0/arch/x86/entry/syscalls/syscall_64.tbl

echo "Adcione ao final do arquivo o prototipo da(s) sua(s) syscalls "
echo "Exemplo: asmlinkage long sys_hello(void)"

sudo gedit /usr/src/linux-source-4.15.0/include/linux/syscalls.h

echo "Compilando Kernel: "
cd /usr/src/linux-source-4.15.0/ && sudo make clean
cd /usr/src/linux-source-4.15.0/ && sudo make -j2

echo "Modules_install"
cd /usr/src/linux-source-4.15.0/ && sudo make modules_install -j2

echo "Make install"

cd /usr/src/linux-source-4.15.0/ && sudo make install -j2

sudo reboot
