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
    if (argc != 3) {
        printf("Usage: %s <IP> <PORT>\n", argv[0]);
        exit(1);
    }
    
    int port=atoi(argv[2]);
    printf("%s, %d\n",argv[1],port);

    int server_fd;
    ssl_context ssl;
  
    x509_crt cacert;
    entropy_context entropy;
    ctr_drbg_context ctr_drbg;
    char const *pers = "ssl_client";

    

   
    x509_crt_init(&cacert);
  entropy_init(&entropy);
   

    // Seed the random number generator
    ctr_drbg_init(&ctr_drbg, entropy_func, &entropy, (const unsigned char *)pers, strlen(pers));

    // Load the trusted CA certificate
    // Note: In a real application, you might want to load a list of trusted CA certificates
    //mbedtls_x509_crt_parse_file(&cacert, "cert.pem");
    
    if(x509_crt_parse_file(&cacert, "server.crt") != 0) {
    printf("Failed to parse CA certificate\n");
    exit(1);
}
     net_connect(&server_fd, argv[1], port);
     
    // Setup SSL configuration
        ssl_init(&ssl);
   ssl_set_endpoint(&ssl, SSL_IS_CLIENT);
    ssl_set_authmode(&ssl, SSL_VERIFY_OPTIONAL);
    ssl_set_ca_chain(&ssl, &cacert, NULL,NULL);
    ssl_set_rng(&ssl, ctr_drbg_random, &ctr_drbg);

    // Setup SSL context using the configuration
   

    // Connect to server
    
    ssl_set_bio(&ssl, net_recv, &server_fd, net_send, &server_fd);

    if (ssl_handshake(&ssl) != 0) {
        printf("Failed handshake\n");
        exit(1);
    }

    // Send a simple HTTP GET request
   // const char *request = "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
    const char *request = "Hello i am client";
    ssl_write(&ssl, (unsigned char *)request, strlen(request));

    char buffer[BUFFER_SIZE];
    int bytes;
    while ((bytes = ssl_read(&ssl, (unsigned char *)buffer, BUFFER_SIZE - 1)) > 0) {
        buffer[bytes] = '\0';
        printf("%s", buffer);
    }

   

    net_close(server_fd);
    ssl_free(&ssl);
    
    x509_crt_free(&cacert);
    ctr_drbg_free(&ctr_drbg);
    entropy_free(&entropy);

    return 0;
}

