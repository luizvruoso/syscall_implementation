#include <linux/init.h>           // Macros used to mark up functions e.g. __init __exit
#include <linux/module.h>         // Core header for loading LKMs into the kernel
#include <linux/device.h>         // Header to support the kernel Driver Model
#include <linux/kernel.h>         // Contains types, macros, functions for the kernel
#include <linux/fs.h>             // Header for the Linux file system support
#include <linux/uaccess.h>        // Required for the copy to user function
#include <linux/mutex.h>	  // Required for the mutex functionality
#include <linux/moduleparam.h>

#include <crypto/hash.h>
#include <linux/stat.h>
#include <linux/crypto.h>
#include <linux/random.h>
#include <linux/mm.h>
#include <linux/scatterlist.h>
#include <crypto/skcipher.h>
#include <linux/err.h>
#include <linux/vmalloc.h>


asmlinkage ssize_t write_crypt(int fd, const void*buf, size_t nbytes);
asmlinkage ssize_t read_crypt(int fd, void*buf, size_t nbytes);



struct skcipher_def {
    struct scatterlist sg; 
    struct crypto_skcipher *tfm;
    struct skcipher_request *req; //struct com definições para solicitar a criptografia
    struct crypto_wait wait; // struct para requisicao
};

static unsigned int test_skcipher_encdec(struct skcipher_def *sk, int enc);
static int encode_trigger( char msgToEncypt[], int size_of_string, char keyFromUser[]);
static int decode_trigger(char msgToDecrypt[], int size_of_string, char keyFromUser[]);
void decrypt(char *string,int size_of_string, char* localKey);
void encrypt(char *string,int size_of_string ,char* localKey);
int hex_to_int(char c);
int hex_to_ascii(char c, char d);
int getRightTotalBlocksBasedOnStringSize(int size_of_string);
/* Perform cipher operation */
static unsigned int test_skcipher_encdec(struct skcipher_def *sk, int enc)
{
    int rc;
	char *resultdata = NULL;

    if (enc)
        rc = crypto_wait_req(crypto_skcipher_encrypt(sk->req), &sk->wait);
    else
        rc = crypto_wait_req(crypto_skcipher_decrypt(sk->req), &sk->wait);

    if (rc)
        printk("skcipher encrypt returned with result %d\n", rc);



    return rc;
}


int getRightTotalBlocksBasedOnStringSize(int size_of_string){

    if(size_of_string%16 != 0){
     if( (size_of_string/16)+1 > 16) return 16;
     else return (size_of_string/16)+1;

    }
    else return size_of_string/16;


}




/* Initialize and trigger cipher operation */
static int encode_trigger( char msgToEncypt[], int size_of_string, char keyFromUser[]) //Inicia a encriptção da string
{
    struct skcipher_def sk;
    struct crypto_skcipher *skcipher = NULL;
    struct skcipher_request *req = NULL;
    char *scratchpad = NULL;
    //char *ivdata = NULL;
    unsigned char key[32];
    int ret = -EFAULT;
    char *resultdata = NULL;

    //printk("MSG: %s, Key: %s, IV: %s \n",msgToEncypt, keyFromUser, ivFromUser);


    skcipher = crypto_alloc_skcipher("ecb(aes)", 0, 0);
    if (IS_ERR(skcipher)) {
        pr_info("could not allocate skcipher handle\n");
        return PTR_ERR(skcipher);
    }

    req = skcipher_request_alloc(skcipher, GFP_KERNEL);
    if (!req) {
        pr_info("could not allocate skcipher request\n");
        ret = -ENOMEM;
        goto out;
    }

    skcipher_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG,
    	crypto_req_done,
        &sk.wait);


    strcpy(key, keyFromUser);
    if (crypto_skcipher_setkey(skcipher, key, 16)) {
        pr_info("key could not be set\n");
        ret = -EAGAIN;
        goto out;
    }
    print_hex_dump(KERN_DEBUG, "KEY: ", DUMP_PREFIX_NONE, 16, 1,
               key, 16, true);
			
		

 
    scratchpad = vmalloc(256);
    memset(scratchpad, 0, 256); //zerando scratchpad

    if (!scratchpad) {
        pr_info("could not allocate scratchpad\n");
        goto out;
    }

    memcpy(scratchpad, msgToEncypt, 256);
    memset(msgToEncypt, 0, 256);




    //print_hex_dump(KERN_DEBUG, "Scratchpad: ", DUMP_PREFIX_NONE, 16, 1, scratchpad, 16, true);

    sk.tfm = skcipher;
    sk.req = req;
    int i=0;

    for(i=0; i < getRightTotalBlocksBasedOnStringSize(size_of_string); i++){
        /* We encrypt one block */
        sg_init_one(&sk.sg, scratchpad+(i*16), 16); //inicializa sk.sg com o conteudo do scratchpad
        skcipher_request_set_crypt(req, &sk.sg, &sk.sg, 16, NULL);  // https://manpages.debian.org/testing/linux-manual-4.8/skcipher_request_set_crypt.9
        crypto_init_wait(&sk.wait);
        /* encrypt data */
        ret = test_skcipher_encdec(&sk, 1);
          if (ret)
            goto out;

        resultdata = sg_virt(&sk.sg);
        memcpy(msgToEncypt+(i*16), resultdata, 16);

    }


    pr_info("Encryption triggered successfully\n");

out:
    if (skcipher)
        crypto_free_skcipher(skcipher);
    if (req)
        skcipher_request_free(req);
    if (scratchpad)
        vfree(scratchpad);
    return ret;
}



/* DECODE */
static int decode_trigger(char msgToDecrypt[], int size_of_string,char keyFromUser[]) //Inicia a decriptção da string
{


    struct skcipher_def sk;
    struct crypto_skcipher *skcipher = NULL;
    struct skcipher_request *req = NULL;
    char *scratchpad = NULL;
    //char *ivdata = NULL;
    unsigned char key[32];
    int ret = -EFAULT;
	char *resultdata = NULL;



    printk("MSG: %s, Key: %s\n", msgToDecrypt, keyFromUser);


    skcipher = crypto_alloc_skcipher("ecb(aes)", 0, 0); //Padrãozin

    if (IS_ERR(skcipher)) {
        pr_info("could not allocate skcipher handle\n");
        return PTR_ERR(skcipher);
    }

    req = skcipher_request_alloc(skcipher, GFP_KERNEL);

    if (!req) {
        pr_info("could not allocate skcipher request\n");
        ret = -ENOMEM;
        goto out;
    }

    skcipher_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG,crypto_req_done, &sk.wait);


    strcpy(key, keyFromUser);

    //ao invés de skcipher, key mudar para key, skcipher para decriptografar
    if (crypto_skcipher_setkey(skcipher, key, 16)) {
        pr_info("key could not be set\n");
        ret = -EAGAIN;
        goto out;
    }

    print_hex_dump(KERN_DEBUG, "KEY: ", DUMP_PREFIX_NONE, 16, 1, key, 16, true);
			

    scratchpad = vmalloc(256);
    memset(scratchpad, 0, 256); //zerando scratchpad

    if (!scratchpad) {
        pr_info("could not allocate scratchpad\n");
        goto out;
    }

    memcpy(scratchpad, msgToDecrypt, 256);
    memset(msgToDecrypt, 0, 256); //aqui vai estar o return da decrypt


    printk("String para decriptar:%s", msgToDecrypt); 


    print_hex_dump(KERN_DEBUG, "Scratchpad: ", DUMP_PREFIX_NONE, 16, 1, scratchpad, 16, true);

    sk.tfm = skcipher;
    sk.req = req;
    int i =0;
    for( i=0; i < getRightTotalBlocksBasedOnStringSize(size_of_string); i++){
        /* We encrypt one block */
        sg_init_one(&sk.sg, scratchpad+(i*16), 16); //inicializa sk.sg com o conteudo do scratchpad
        skcipher_request_set_crypt(req, &sk.sg, &sk.sg, 16, NULL);  // solicita a 
        crypto_init_wait(&sk.wait);
         /* decrypt data */ 
        ret = test_skcipher_encdec(&sk, 0);
        if (ret)
            goto out;

	    resultdata = sg_virt(&sk.sg);
        
        memcpy(msgToDecrypt+(i*16), resultdata, 16);


    }
   
    pr_info("Decrypt triggered successfully\n");




out:
    if (skcipher)
        crypto_free_skcipher(skcipher);
    if (req)
        skcipher_request_free(req);
    if (scratchpad)
        vfree(scratchpad);
    return ret;
}


void decrypt(char *string,int size_of_string, char* localKey){

	print_hex_dump(KERN_DEBUG, "MENSAGEM CRIPTOGRADA - P/ DECRIPT: ", DUMP_PREFIX_NONE, 16, 1,
               string, 16, true);

    int i = 0;
    char aux[256]={0};

    

    memcpy(aux, string, 256);

    print_hex_dump(KERN_DEBUG, "AUX AFTER COPY: ", DUMP_PREFIX_NONE, 256, 1, aux, 256, true);

    decode_trigger(aux, size_of_string,localKey);
    memset(string, 0, 256);
    memcpy(string, aux, 256);



	

    print_hex_dump(KERN_DEBUG, "MENSAGEM DECRIPTOGRAFADA: ", DUMP_PREFIX_NONE, 256, 1,
               string, 256, true);


    //print_hex_dump(KERN_DEBUG, "Result Data Decrypt: ", DUMP_PREFIX_NONE, 16, 1, aux, 16, true);

	return;
}


void encrypt(char *string,int size_of_string ,char* localKey){
	//printk(KERN_INFO "Chave %s \n",localKey);	
     print_hex_dump(KERN_DEBUG, "MENSAGEM USER EM HEXA: ", DUMP_PREFIX_NONE, 256, 1,
               string, 256, true);
    encode_trigger(string, size_of_string,localKey);
    print_hex_dump(KERN_DEBUG, "MENSAGEM CRIPTOGRAFADA: ", DUMP_PREFIX_NONE, 256, 1,
               string, 256, true);
    return;
}


int hex_to_int(char c){
    int result;

    if(c >= 'a')
        result = c - 97 + 10;
    else
        result = c - 48;

    return result;
}


int hex_to_ascii(char c, char d){
        int high = hex_to_int(c) * 16;
        int low = hex_to_int(d);

        printk("High + Low: %d Char: %c\n", high + low, high + low);

        return high+low;

}
