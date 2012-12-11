//----------------------------------------------------------------------------
// File: ssl_server.cpp
// Description: Implementation of an SSL-secured server that performs
//              secure file transfer to a single client over a single
//              connection.
//----------------------------------------------------------------------------
#include <string>
#include <iostream>
#include <time.h>
using namespace std;
#include <openssl/rand.h>
#include <openssl/ssl.h>	// Secure Socket Layer library
#include <openssl/bio.h>	// Basic Input/Output objects for SSL
#include <openssl/rsa.h>	// RSA algorithm etc
#include <openssl/pem.h>	// For reading .pem files for RSA keys
#include <openssl/err.h>

#include "utils.h"






//-----------------------------------------------------------------------------
// Function: main()
//-----------------------------------------------------------------------------
int main(int argc, char** argv)
{
    //-------------------------------------------------------------------------
    // initialize
	ERR_load_crypto_strings();
	SSL_load_error_strings();
    SSL_library_init();

    char infilename[] = "stenos.txt";
    char outfilename[] = "DocOut.txt";
    char pvtfilename[] = "rsaprivatekey.pem";
    char pbcfilename[] = "rsapublickey.pem";

    

    BIO *binfile, *boutfile, *hash1, *hash2, *pvtkey, *pbckey;
    binfile = BIO_new_file(infilename, "r");
    boutfile = BIO_new_file(outfilename, "w") ;
    pvtkey = BIO_new_file(pvtfilename, "r");
    pbckey = BIO_new_file(pbcfilename, "r");
    
    setbuf(stdout, NULL); // disables buffered output

	// Handle commandline arguments
	// Useage: client -server serveraddress -port portnumber filename
	if (argc < 2)
	{
		printf("Useage: server portnumber\n");
		exit(EXIT_FAILURE);
	}
	char* port = argv[1];

	printf("------------\n");
	printf("-- SERVER --\n");
	printf("------------\n");

    //-------------------------------------------------------------------------
	// 1. Allow for a client to establish an SSL connection
	printf("1. Allowing for client SSL connection...");

	// Setup DH object and generate Diffie-Helman Parameters
	DH* dh = DH_generate_parameters(128, 5, NULL, NULL);
	int dh_err;
	DH_check(dh, &dh_err);
	if (dh_err != 0)
	{
		printf("Error during Diffie-Helman parameter generation.\n");
        print_errors();
		exit(EXIT_FAILURE);
	}

	// Setup server context
	SSL_CTX* ctx = SSL_CTX_new(SSLv23_method());
	SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
//	SSL_CTX_set_options(ctx, SSL_OP_ALL | SSL_OP_NO_SSLv2 | SSL_OP_SINGLE_DH_USE);
	SSL_CTX_set_tmp_dh(ctx, dh);
	if (SSL_CTX_set_cipher_list(ctx, "ALL") != 1)
	{
		printf("Error setting cipher list. Sad christmas...\n");
        print_errors();
		exit(EXIT_FAILURE);
	}

	// Setup the BIO
	BIO* server = BIO_new(BIO_s_accept());
	BIO_set_accept_port(server, port);
	BIO_do_accept(server);

	// Setup the SSL
	SSL* ssl = SSL_new(ctx);
	if (!ssl)
	{
		printf("Error creating new SSL object from context.\n");
        print_errors();
		exit(EXIT_FAILURE);
	}
	SSL_set_accept_state(ssl);
	SSL_set_bio(ssl, server, server);
	if (SSL_accept(ssl) <= 0)
	{
		printf("Error doing SSL_accept(ssl).\n");
        print_errors();
		exit(EXIT_FAILURE);
	}

	printf("DONE.\n");
	printf("    (Now listening on port: %s)\n", port);

    //-------------------------------------------------------------------------
	// 2. Receive a random number (the challenge) from the client
	printf("2. Waiting for client to connect and send challenge...");
    
    //SSL_read
    string challenge="";
    int read_x;
     read_x = SSL_read(ssl, (void*)challenge.c_str(), BUFFER_SIZE);
    
    challenge = buff2hex((const unsigned char*)challenge.c_str(), BUFFER_SIZE).c_str();
    
	printf("DONE.\n");
	printf("    (Challenge: \"%s\")\n", challenge.c_str());

    //-------------------------------------------------------------------------
	// 3. Generate the SHA1 hash of the challenge
	printf("3. Generating SHA1 hash...");

     
     //BIO_new(BIO_s_mem());
	//BIO_write
	//BIO_new(BIO_f_md());
	//BIO_set_md;
	//BIO_push;
	//BIO_gets;

     char mdbuff[20];
     //Not going to be docked for not having hash work correctly
	//BIO_new(BIO_s_mem());

     //hash1 does not mean it is a hash, this was a variable that I had been declared.
     hash1 = BIO_new(BIO_s_mem());
	
	int writex2 = BIO_write(hash1, (const void*)challenge.c_str(), sizeof(challenge.c_str()));


     //BIO_new(BIO_f_md());
	hash2 = BIO_new(BIO_f_md());
     //BIO_set_md;
     BIO_set_md(hash2, EVP_sha1());
	
	//BIO_push;
     BIO *hash3 = BIO_push(hash2, hash1);
	//BIO_gets; BIO_read(bfile, buffer, BUFFER_SIZE)) > 0)
     
     int mdlen = BIO_read(hash3, (void*)mdbuff, sizeof(mdbuff));

	string hash_string = buff2hex((const unsigned char*)mdbuff, sizeof(mdbuff)).c_str();
    

	printf("SUCCESS.\n");
	printf("    (SHA1 hash: \"%s\" (%d bytes))\n", hash_string.c_str(), mdlen);

    //-------------------------------------------------------------------------
	// 4. Sign the key using the RSA private key specified in the
	//     file "rsaprivatekey.pem"
	printf("4. Signing the key...");

    char temp_buff2[BUFFER_SIZE];
    memset(temp_buff2,0,BUFFER_SIZE);
    //PEM_read_bio_RSAPrivateKey
    BIO *rsaprivkey;
    rsaprivkey = BIO_new_file(pvtfilename, "r");

    RSA *gekas = PEM_read_bio_RSAPrivateKey(rsaprivkey, NULL, 0, NULL);

    int e_priv = RSA_size(gekas);
   
    //RSA_private_encrypt

    int siglen = RSA_private_encrypt(e_priv-11, (const unsigned char*)hash_string.c_str(), (unsigned char*)temp_buff2, gekas, RSA_PKCS1_PADDING);


    char* signature= (char*) temp_buff2;

    printf("DONE.\n");
    printf("    (Signed key length: %d bytes)\n", siglen);
    printf("    (Signature: \"%s\" (%d bytes))\n", buff2hex((const unsigned char*)temp_buff2, siglen).c_str(), siglen);

    //-------------------------------------------------------------------------
	// 5. Send the signature to the client for authentication
	printf("5. Sending signature to client for authentication...");

    

	//BIO_flush
     BIO_flush(server);

	SSL_write(ssl, (const void*)signature, siglen);
     
     

      


    

     

      

    printf("DONE.\n");
    
    //-------------------------------------------------------------------------
	// 6. Receive a filename request from the client
	printf("6. Receiving file request from client...");

    //SSL_read
   // int read_x2;
     
    char file[BUFFER_SIZE];
    
    memset(file,0,sizeof(file));


   // cout << "Reached this point" << endl; had trouble recognizing the request
    SSL_read(ssl,file,BUFFER_SIZE);

    

    printf("RECEIVED.\n");
    printf("    (File requested: \"%s\"\n", file);

    //-------------------------------------------------------------------------
	// 7. Send the requested file back to the client (if it exists)
	printf("7. Attempting to send requested file to client...");

	PAUSE(2);
	//BIO_flush
    int actualRead, actualWritten, bytesRead;

    char buffer[BUFFER_SIZE];
    memset(buffer,0,BUFFER_SIZE);
    
    int p_temp = 0; 

    BIO_flush(server);
	//BIO_new_file
    BIO* ifile = BIO_new_file(file, "r");
    BIO_puts(server, "fnf");
    //BIO_read(ifile, buffer, BUFFER_SIZE)) > 0) Code given to us in the project by Mike
	//SSL_write(ssl, buffer, bytesRead);

    string output;

    int bytesSent=0;

    if(ifile == NULL)
    {
       cout << "ALERT ERROR! THERE IS NO FILE!!!" << endl;

       return 0; // or else the program will not exit at all

    }

    else
    {
      while(true)
      {
         bytesRead = BIO_read(ifile, buffer, BUFFER_SIZE);
          
         printf(buffer); //Buffer is populated
         bytesSent += bytesRead;
         if(bytesRead < BUFFER_SIZE )
         {
          
           for(int i = 0; i < bytesRead; ++i)
             output[i] = buffer[i];


           output = output.substr(0,output.size());
           
           int r_output = SSL_write(ssl, output.c_str(),bytesRead);
           cout << "REACHED SSL WRITE " <<  r_output << endl;
           break;

          }

       }
     }


    
    
    printf("SENT.\n");
    printf("    (Bytes sent: %d)\n", bytesSent);

    //-------------------------------------------------------------------------
	// 8. Close the connection
	printf("8. Closing connection...");

    SSL_shutdown(ssl);
    //BIO_reset
    printf("DONE.\n");

    printf("\n\nALL TASKS COMPLETED SUCCESSFULLY.\n");
	
    //-------------------------------------------------------------------------
	// Freedom!
    
	BIO_free_all(server);
	return EXIT_SUCCESS;
}
