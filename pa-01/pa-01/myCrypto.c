/*----------------------------------------------------------------------------
My Cryptographic Library

FILE:   myCrypto.c

Written By: 
     1- Jacob Zorniak
     
Submitted on: 
----------------------------------------------------------------------------*/

#include "myCrypto.h"

void handleErrors( char *msg)
{
    fprintf( stderr , "%s\n" , msg ) ;
    ERR_print_errors_fp(stderr);
    abort();
}

//-----------------------------------------------------------------------------

int encryptFile( int fd_in, int fd_out, unsigned char *key, unsigned char *iv )
{
    int status;
    unsigned len = 0, encryptedLen = 0;
    uint8_t plaintext_buffer[1008], ciphertext_buffer[CIPHER_LEN_MAX];
    uint8_t *pPlaintext = plaintext_buffer, *pCiphertext = ciphertext_buffer;

    /* Create and initialise the context */
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if(!ctx)
        handleErrors("encrypt: failed to creat CTX");

    //Initialise the encryption operation.
    status = EVP_EncryptInit_ex(ctx, ALGORITHM(), NULL, key, iv);
    if(status != 1)
            handleErrors("encrypt: failed to EncryptInit_ex");

    //Call EncryptUpdate as many times as needed (e.g. inside a loop)
    //to perform regular encryption
    int bytes_read;
    while((bytes_read = read(fd_in, pPlaintext, 1008)) != 0)
    {
        status = EVP_EncryptUpdate(ctx, pCiphertext, &len, pPlaintext, bytes_read);
        if(status != 1)
            handleErrors("encrypt: failed to EncryptUpdate");
        write(fd_out, pCiphertext, len);
        encryptedLen += len;
    }
    
    //Adjust pCiphertext pointer in case of additional ciphertext
    pCiphertext += len;

    //Finalize the encryption.
    status = EVP_EncryptFinal_ex(ctx, pCiphertext, &len);
    if(status != 1)
        handleErrors("encrypt: failed to EncryptFinal_ex");
    encryptedLen += len;    // len could be 0 if no additional cipher text was generated

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return encryptedLen;    
}

//-----------------------------------------------------------------------------

int decryptFile( int fd_in, int fd_out, unsigned char *key, unsigned char *iv )
{
    int status;
    unsigned len = 0, decryptedLen = 0;
    uint8_t ciphertext_buffer[CIPHER_LEN_MAX], plaintext_buffer[1016];
    uint8_t *pCiphertext = ciphertext_buffer, *pPlaintext = plaintext_buffer;

    /* Create and initialise the context */
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if(!ctx)
        handleErrors("decrypt: failed to creat CTX");

    //Initialise the decryption operation.
    status = EVP_DecryptInit_ex(ctx, ALGORITHM(), NULL, key, iv);
    if(status != 1)
        handleErrors("decrypt: failed to DecryptInit_ex");

    EVP_CIPHER_CTX_set_padding(ctx, 0);
    //Call DecryptUpdate as many times as needed (e.g. inside a loop)
    //to perfrom regular decryption
    int bytes_read;
    while((bytes_read = read(fd_in, pCiphertext, CIPHER_LEN_MAX)) != 0)
    {
        status = EVP_DecryptUpdate(ctx, pPlaintext, &len, pCiphertext, bytes_read);
        if(status != 1)
            handleErrors("decrypt: failed to DecryptUpdate");
        write(fd_out, pPlaintext, len);
        decryptedLen += len;
    }

    //Adjust pPlaintext pointer in case more decrypted/plaintext is generated
    pPlaintext += len;

    //Finalize the decryption
    status = EVP_DecryptFinal_ex(ctx, pPlaintext, &len);
    if(status != 1)
        handleErrors("decrypt: failed to DecryptFinal_ex");
    decryptedLen += len;

    /* Clean up*/
    EVP_CIPHER_CTX_free(ctx);

    return decryptedLen;
}

