#include<stdio.h>
#include<string.h>
#include<stdlib.h>
#include<ldap.h>
#include <unistd.h>
#include <arpa/inet.h>
#include "polarssl/net.h"
#include "polarssl/ssl.h"
#include "polarssl/entropy.h"
#include "polarssl/ctr_drbg.h"
#include "polarssl/debug.h"
#include "polarssl/error.h"
#include "polarssl/certs.h"

int server_fd;
    ssl_context ssl;
  
    x509_crt cacert;
    entropy_context entropy;
    ctr_drbg_context ctr_drbg;
    char const *pers = "ssl_client";
    
int main(int argc ,char *argv[])
{
	LDAP *ld;
	LDAPMessage *result, *e;
	char *dn;
	char s[100];
	int rc;
	secure();
//URI for ldap server
	char *uri = "ldap://192.168.11.14:636";
//association with LDAP server / returns a handle to an LDAP session
	rc = ldap_initialize(&ld, uri);
    	if (rc != LDAP_SUCCESS) 
	{
        	fprintf(stderr, "ldap_initialize: %s\n", ldap_err2string(rc));
        	return 1;
    	}
	
//Binding process
	char *ldap_pwd = "Password1";
	char *FIND_DN = "DC=thesecmaster,DC=com";
	rc = ldap_simple_bind_s(ld, FIND_DN, ldap_pwd);
	if (rc != LDAP_SUCCESS)
	{
		perror("-[+]_Not_binded");
		exit(1);
	}
//searching for the entry
	rc = ldap_search_ext_s( ld, FIND_DN, LDAP_SCOPE_SUBTREE,"(objectclass=*)", NULL, 0, NULL,NULL,NULL,LDAP_NO_LIMIT, &result );
	if (rc != LDAP_SUCCESS) 
	{
		perror("-[+]_Match_Not found");
		exit(1);

	}
	e = ldap_first_entry(ld,result );
	while(e != NULL)
	{
		dn = ldap_get_dn(ld,e);
		if(dn != NULL) 
		{
			printf("dn: %s\n", dn);
			ldap_memfree(dn);
		}
		e=ldap_next_entry(ld, e);
	}

	ldap_msgfree(result);
	ldap_unbind_ext(ld, NULL, NULL);


	return 0;

}
void secure(){


    x509_crt_init(&cacert);
  entropy_init(&entropy);
   

    // Seed the random number generator
    if(ctr_drbg_init(&ctr_drbg, entropy_func, &entropy, (const unsigned char *)pers, strlen(pers))!=0){
    printf("unable to generate random number\n");
    exit(1);
    }

    // Load the trusted CA certificate

    
    if(x509_crt_parse_file(&cacert, "ldap_server.crt") != 0) {
    printf("Failed to parse CA certificate\n");
    exit(1);
}
     if(net_connect(&server_fd, "192.168.11.14", 636)!=0){
     printf("Failed to connect\n");
     exit(1);
     }
     
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
    }

    void clean(){
            net_close(server_fd);
    ssl_free(&ssl);
    
    x509_crt_free(&cacert);
    ctr_drbg_free(&ctr_drbg);
    entropy_free(&entropy);
    }
