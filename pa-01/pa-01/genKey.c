/*
   Generate encryption key / IV and save to binary files
*/

#include <stdint.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>

/* OpenSSL headers */
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

void main()
{
    uint8_t key[EVP_MAX_KEY_LENGTH] ,
             iv[EVP_MAX_IV_LENGTH] ; 
    
    unsigned key_len = EVP_MAX_KEY_LENGTH ;
    unsigned iv_len  = EVP_MAX_IV_LENGTH  ;
    int fd_key, fd_iv ;

    fd_key = open("key.bin", O_WRONLY|O_CREAT|O_TRUNC, S_IRUSR|S_IWUSR)  ;
    if( fd_key == -1 )
    {
        fprintf(stderr, "Unable to open file for key\n");
        exit(-1) ;
    }

    fd_iv = open("iv.bin", O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR)  ;
    if( fd_iv == -1 )
    {
        fprintf(stderr, "Unable to open file for IV\n");
        exit(-1) ;
    }

    // Genrate the random key & IV
    RAND_bytes( key , key_len );
    RAND_bytes( iv  , iv_len  );
    
    write( fd_key , key , key_len );
    write( fd_iv  , iv  , iv_len );
    
    close( fd_key ) ;
    close( fd_iv ) ;

}


