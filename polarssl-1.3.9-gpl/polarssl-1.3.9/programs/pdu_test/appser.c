// server_mbedtls.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include "polarssl/net.h"
#include "polarssl/ssl.h"
#include "polarssl/entropy.h"
#include "polarssl/ctr_drbg.h"
#include "polarssl/debug.h"
#include "polarssl/error.h"
#include "polarssl/certs.h"

#define BUFFER_SIZE 4096
int main(int argc, char *argv[]) {
   if (argc != 2) {
        printf("Usage: %s <PORT>\n", argv[0]);
        exit(1);
    }
    int p=atoi(argv[1]);
   

    int listen_fd = -1;
    int client_fd = -1;
    ssl_context ssl;
    
    x509_crt srvcert;
    pk_context rsa_key;
    entropy_context entropy;
    ctr_drbg_context ctr_drbg;
    char const *pers = "ssl_server";

    memset( &rsa_key, 0, sizeof( rsa_key ) );
    ssl_init(&ssl);
    x509_crt_init(&srvcert);
    pk_init(&rsa_key);
    entropy_init(&entropy);
    

if(x509_crt_parse_file(&srvcert, "cert.pem") != 0) {
    printf("Failed to parse certificate\n");
    exit(1);
}
if(pk_parse_keyfile(&rsa_key, "key.pem", NULL) != 0) {
    printf("Failed to parse private key\n");
    exit(1);
}
    // Bind and listen
    net_bind(&listen_fd, NULL, p);
    
       // Seed the random number generator
    ctr_drbg_init(&ctr_drbg, entropy_func, &entropy, (const unsigned char *)pers, strlen(pers));
    
    // Setup SSL configuration
    ssl_set_endpoint(&ssl, SSL_IS_SERVER);
    ssl_set_authmode( &ssl, SSL_VERIFY_NONE );
    ssl_set_rng(&ssl, ctr_drbg_random, &ctr_drbg);
    ssl_set_ca_chain(&ssl, srvcert.next, NULL,NULL);
    ssl_set_own_cert(&ssl, &srvcert, &rsa_key);

    // Setup SSL context using the configuration

     printf("Listening to port %s...\n",argv[1]);
    

    while (1) {
        net_accept(listen_fd, &client_fd, NULL);

        ssl_set_bio(&ssl, net_recv, &client_fd, net_send, &client_fd);
        if (ssl_handshake(&ssl) != 0) {
            printf("Failed handshake\n");
            exit(1);
        }
	
	
	char buffer[BUFFER_SIZE];
	int bytes;
	bytes = ssl_read(&ssl, (unsigned char *)buffer, BUFFER_SIZE - 1);
        buffer[bytes] = '\0';
        printf("%s", buffer);
   
	
	
        const char *response = "HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\nHello, TLSv1.2!";
        ssl_write(&ssl, (unsigned char *)response, strlen(response));

        ssl_close_notify(&ssl);
        net_close(client_fd);
        pk_free(&rsa_key);
    }

    x509_crt_free(&srvcert);
    net_close(listen_fd);
    ssl_free(&ssl);
  ctr_drbg_free(&ctr_drbg);
  entropy_free(&entropy);

    return 0;
}

