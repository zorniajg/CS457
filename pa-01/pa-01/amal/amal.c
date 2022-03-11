/*-------------------------------------------------------------------------------------------------
Programming Lab-01    Generate ecryption key / IV and save to binary files

FILE:    mamal.c

Written By:    1- Mohamed Aboutabl
Jacob Zorniak
----------------------------------------------------------------------------------------------------*/

#include "../myCrypto.h"

void main(int argc, char** argv)
{

    uint8_t key[SYMMETRIC_KEY_LEN] , iv[INITVECTOR_LEN];
    unsigned key_len = 32;  //i.e. 256 bits
    unsigned iv_len = 16;  //i.e. 128 bits

    /* Initialise the crypto library */
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();
  
    //Open Amal's log file
    FILE *log = fopen("amal/logAmal.txt", "w");
    if(!log)
    {
	    fprintf(stderr, "Amal: Could not create log file\n");
	    exit(-1);
    }

    //Get file descriptor for pipes
    int fd_AtoB_control, fd_AtoB_data;
    fd_AtoB_control = atoi(argv[1]);
    fd_AtoB_data = atoi(argv[2]);

    //Get the session symmetric key
    int fd_key, fd_iv, fd_bunny;
    fd_key = open("amal/key.bin", O_RDONLY);
    if(fd_key == -1)
    {
	    fprintf(stderr, "\nAmal: Could not open key.bin\n");
	    fclose(log); exit(-1);
    }
    read(fd_key, key, key_len);

    //Print symmetric key to Amal's log
    fprintf(log, "\nUsing this symmetric key of length %d bytes\n", key_len);
    BIO_dump_fp(log, (const char *) key, key_len);
    close(fd_key);

    //Get the session Initial Vector 
    fd_iv = open("amal/iv.bin", O_RDONLY);
    if(fd_iv == -1)
    {
	    fprintf(stderr, "\nAmal: Could not open iv.bin\n");
	    fclose(log); exit(-1);
    }
    read(fd_iv, iv, iv_len);

    //Print the initial vector to Amal's log
    fprintf(log, "\nUsing this Initial Vector of length %d bytes\n", iv_len);
    BIO_dump_fp(log, (const char *) iv, iv_len);
    close(fd_iv);

    //Open symbolic link to read in bunny.mp4
    fd_bunny = open("../bunny.mp4", O_RDONLY);
    if(fd_bunny == -1)
    {
            fprintf(stderr, "\nAmal: Could not open bunny.mp4\n");
            fclose(log); exit(-1);
    }
    
    //Call encryptFile() passing in the mp4 and write-end of pipe file descriptors
    encryptFile(fd_bunny, fd_AtoB_data, key, iv);

    //Close files & file descriptors
    close(fd_bunny);
    fclose(log);

    /* Clean up */
    EVP_cleanup();
    ERR_free_strings();
}
