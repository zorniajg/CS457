/*---------------------------------------------------------------------------------------------------------------
Programming Lab-01     Generate ecryption key / IV and save to binary files

FILE:    basim/basim.c

Written By: 1- Dr. Mohamed Aboutal
Jacob Zorniak
----------------------------------------------------------------------------------------------------------------*/

#include "../myCrypto.h"

void main(int argc, char** argv)
{
    uint8_t key[SYMMETRIC_KEY_LEN] , iv[INITVECTOR_LEN];
    unsigned key_len = 32;  //i.e. 256 bits
    unsigned iv_len = 16;  //i.e. 128 bits

    /* Initialise the crypto library */
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();

    //Open Basim's log file
    FILE *log = fopen("basim/logBasim.txt", "w");
    if(!log)
    {
            fprintf(stderr, "Basim: Could not create log file\n");
            exit(-1);
    }

    //Get file descriptor for pipes
    int fd_AtoB_control, fd_AtoB_data;
    fd_AtoB_control = atoi(argv[1]);
    fd_AtoB_data = atoi(argv[2]);

    //Get the session symmetric key
    int fd_key, fd_iv;
    fd_key = open("basim/key.bin", O_RDONLY);
    if(fd_key == -1)
    {
            fprintf(stderr, "\nBasim: Could not open key.bin\n");
            fclose(log); exit(-1);
    }
    read(fd_key, key, key_len);

    //Print symmetric key to Basim's log
    fprintf(log, "\nUsing this symmetric key of length %d bytes\n", key_len);
    BIO_dump_fp(log, (const char *) key, key_len);
    close(fd_key);
    
     //Get the session Initial Vector
    fd_iv = open("basim/iv.bin", O_RDONLY);
    if(fd_iv == -1)
    {
            fprintf(stderr, "\nBasim: Could not open iv.bin\n");
            fclose(log); exit(-1);
    }
    read(fd_iv, iv, iv_len);

    //Print initial vector to Basim's log
    fprintf(log, "\nUsing this Initial Vector of length %d bytes\n", iv_len);
    BIO_dump_fp(log, (const char *) iv, iv_len);
    close(fd_iv);

    //Open new file for decrypted file
    FILE *decr = fopen("bunny.decr", "w");
    if(!decr)
    {
        fprintf(stderr, "Basim: Could not create bunny.decr file\n");
        exit(-1);
    }

    //Turn FILE pointer into file descriptor and call decryptFile()
    int fd_decr = fileno(decr);
    decryptFile(fd_AtoB_data, fd_decr, key, iv);

    //Close files
    fclose(decr);
    fclose(log);

    /* Clean up */
    EVP_cleanup();
    ERR_free_strings();
}
