//----------------------------------------------------------------------------
// File: ssl_client.cpp
// Description: Implementation of an SSL-secured client that performs
//              secure file transfer with a single server over a single
//              connection
//----------------------------------------------------------------------------
#include <string>
#include <iostream>
#include <time.h>               // to seed random number generator
#include <sstream>          // stringstreams
using namespace std;

#include <openssl/ssl.h>	// Secure Socket Layer library
#include <openssl/bio.h>	// Basic Input/Output objects for SSL
#include <openssl/rsa.h>	// RSA algorithm etc
#include <openssl/pem.h>	// For reading .pem files for RSA keys
#include <openssl/err.h>	// ERR_get_error()
#include <openssl/dh.h>		// Diffie-Helman algorithms & libraries

#include "utils.h"

//----------------------------------------------------------------------------
// Function: main()
//----------------------------------------------------------------------------
int main(int argc, char** argv)
{
	//-------------------------------------------------------------------------
    // Initialization

    ERR_load_crypto_strings();
    SSL_library_init();
    SSL_load_error_strings();

    char infilename[] = "stenos.txt";
    char outfilename[] = "DocOut.txt";

  //  char* generated_key[1024];
   // char* decrypted_key[1024];

    char pbcfilename[] = "rsapublickey.pem";

   // unsigned char buffer1[1024] = "testing tesing gekasssss";

    BIO *binfile, *boutfile, *hash, *pbckey;
	binfile = BIO_new_file(infilename, "r");
	boutfile = BIO_new_file(outfilename, "w") ;
 
     pbckey = BIO_new_file(pbcfilename, "r");

    setbuf(stdout, NULL); // disables buffered output
    
    // Handle commandline arguments
	// Useage: client server:port filename
	if (argc < 3)
	{
		printf("Useage: client -server serveraddress -port portnumber filename\n");
		exit(EXIT_FAILURE);
	}
	char* server = argv[1];
	char* filename = argv[2];
	
	printf("------------\n");
	printf("-- CLIENT --\n");
	printf("------------\n");

    //-------------------------------------------------------------------------
	// 1. Establish SSL connection to the server
	printf("1.  Establishing SSL connection with the server...");

	// Setup client context
    SSL_CTX* ctx = SSL_CTX_new(SSLv23_method());
	SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
//	SSL_CTX_set_options(ctx, SSL_OP_ALL|SSL_OP_NO_SSLv2);
	if (SSL_CTX_set_cipher_list(ctx, "ADH") != 1)
	{
		printf("Error setting cipher list. Sad christmas...\n");
        print_errors();
		exit(EXIT_FAILURE);
	}
	
	// Setup the BIO
	BIO* client = BIO_new_connect(server);
	if (BIO_do_connect(client) != 1)
	{
		printf("FAILURE.\n");
        print_errors();
		exit(EXIT_FAILURE);
	}

	// Setup the SSL
    SSL* ssl=SSL_new(ctx);
	if (!ssl)
	{
		printf("Error creating new SSL object from context.\n");
		exit(EXIT_FAILURE);
	}
	SSL_set_bio(ssl, client, client);
	if (SSL_connect(ssl) <= 0)
	{
		printf("Error during SSL_connect(ssl).\n");
		print_errors();
		exit(EXIT_FAILURE);
	}

	printf("SUCCESS.\n");
	printf("    (Now connected to %s)\n", server);

    //-------------------------------------------------------------------------
	// 2. Send the server a random number
	printf("2.  Sending challenge to the server...");
    
    string randomNumber="31337";
	//SSL_write
    int write_x;
  
    write_x = SSL_write(ssl, (const void*)randomNumber.c_str(), BUFFER_SIZE);   


    printf("SUCCESS.\n");
	printf("    (Challenge sent: \"%s\")\n", randomNumber.c_str());

    //-------------------------------------------------------------------------
	// 3a. Receive the signed key from the server
	printf("3a. Receiving signed key from server...");

    char buff[BUFFER_SIZE];
    memset(buff,0,BUFFER_SIZE);
    int len = SSL_read(ssl, (void*)buff, BUFFER_SIZE);
   

    //printf("    (Signed key length: %d bytes)\n", sizeof(buff));
	//SSL_read;

     
     

	printf("RECEIVED.\n");
	printf("    (Signature: \"%s\" (%d bytes))\n", buff2hex((const unsigned char*)buff, len).c_str(), len);

    //-------------------------------------------------------------------------
	// 3b. Authenticate the signed key
	printf("3b. Authenticating key...");


     //BIO_new(BIO_s_mem())
	//BIO_write
	//BIO_new_file
	//PEM_read_bio_RSA_PUBKEY
	//RSA_public_decrypt
	//BIO_free
   
     char temp_buff[BUFFER_SIZE];
     string generated_key = "rsapublickey.pem";
     string decrypted_key ="";
	//BIO_new(BIO_s_mem())
    
     //int  = SSL_read(ssl, (void*)buff, BUFFER_SIZE);
     BIO* buffx = BIO_new(BIO_s_mem());

	//BIO_write
     int zidane = BIO_write(buffx, (void*)buff, BUFFER_SIZE);
	//printf("    (Signed key length: %d bytes)\n", sizeof(buff));
	//PEM_read_bio_RSA_PUBKEY
     BIO *rsapubkey;
     rsapubkey = BIO_new_file(generated_key.c_str(), "r");
     RSA *ninis = PEM_read_bio_RSA_PUBKEY(rsapubkey, NULL, NULL, NULL);
     //RSA_public_decrypt

     int rsa_size = RSA_size(ninis);

     int e_pub;


     e_pub = RSA_public_decrypt(rsa_size, (const unsigned char*)buff, (unsigned char*)temp_buff, ninis, RSA_PKCS1_PADDING); 
	
    
	//BIO_free
	
	generated_key = buff2hex((const unsigned char*)buff, 20).c_str();
	decrypted_key = buff2hex((const unsigned char*)temp_buff, 20).c_str();

     int freex = BIO_free(buffx);
    
	printf("AUTHENTICATED\n");
	printf("    (Generated key: %s)\n", generated_key.c_str());
	printf("    (Decrypted key: %s)\n", decrypted_key.c_str());

    //-------------------------------------------------------------------------
	// 4. Send the server a file request
	printf("4.  Sending file request to server...");

	PAUSE(2);
	//BIO_flush
    int flush = BIO_flush(binfile);
    //BIO_puts
    string f_name = filename;
    int bputs = BIO_puts(binfile, filename);
	//SSL_write
    SSL_write(ssl, filename, f_name.size()); 

    printf("SENT.\n");
	printf("    (File requested: \"%s\")\n", filename);

    //-------------------------------------------------------------------------
	// 5. Receives and displays the contents of the file requested
	printf("5.  Receiving response from server...");

    //BIO_new_file
    //SSL_read
    int read_x2;
     //read_x2 = SSL_read(ssl, (void*)buff, len);
	//BIO_write
	//BIO_free

	printf("FILE RECEIVED.\n");

    //-------------------------------------------------------------------------
	// 6. Close the connection
	printf("6.  Closing the connection...");

	//SSL_shutdown
	
	printf("DONE.\n");
	
	printf("\n\nALL TASKS COMPLETED SUCCESSFULLY.\n");

    //-------------------------------------------------------------------------
	// Freedom!
	SSL_CTX_free(ctx);
	SSL_free(ssl);
	return EXIT_SUCCESS;
	
}
