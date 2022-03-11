/*----------------------------------------------------------------------------
My Cryptographic Library

FILE:   myCrypto.h

              D O    N O T    M O D I F Y     T H I S    F I L E
Written By: 
     1- Dr. Mohamed Aboutabl

----------------------------------------------------------------------------*/

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <fcntl.h>
#include <string.h>
#include <linux/random.h>
#include <assert.h>

/* OpenSSL headers */
#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/rand.h>

// For symmetric-key Encryption/Decryption, 
// use a 256-bit key and AES in CBC mode (with a 128-bit IV)
// Ensure the (key,IV) being used match the specified algorithm
#define ALGORITHM          EVP_aes_256_cbc
#define SYMMETRIC_KEY_LEN  32
#define INITVECTOR_LEN     16

//-----------------------------------------------------------------------------
// pLab-01
//-----------------------------------------------------------------------------
#define CIPHER_LEN_MAX 1024
#define PLAINTEXT_LEN_MAX (CIPHER_LEN_MAX-256)

void       handleErrors( char *msg ) ;

unsigned   encrypt( uint8_t *pPlainText, unsigned plainText_len, 
                    uint8_t *key, uint8_t *iv, uint8_t *pCipherText ) ;

unsigned   decrypt( uint8_t *pCipherText, unsigned cipherText_len, 
                    uint8_t *key, uint8_t *iv, uint8_t *pDecryptedText) ;

//-----------------------------------------------------------------------------
// PA-01
//-----------------------------------------------------------------------------
int    encryptFile( int fd_in, int fd_out, unsigned char *key, unsigned char *iv );
int    decryptFile( int fd_in, int fd_out, unsigned char *key, unsigned char *iv );

