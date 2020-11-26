/*
Gabriel Gonçalves Mattos Santini -  18189084
Luiz Vinicius dos Santos Ruoso - 18233486
Marcelo Germani Olmos -  18048298    
Victor Felipe dos Santos -  18117820
Victor Luiz Fraga Soldera - 18045674
*/

asmlinkage long read_crypt(int fd,char *buf, size_t nbytes);
asmlinkage long write_crypt(int fd,char *buf, size_t nbytes);
