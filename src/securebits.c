/*:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::

Compile:
gcc -o securebits securebits.c  crypto.c base64.c -lssl -lcrypto
Run:
Generacion de llaves publica y privada:
	./securebits -k [directory_name]
Cifrado
	./securebits [options ] -e  [-in plaintext |-f file_name] [-o filename] 
Descifrado
	./securebits [options ] -d  [-in ciphertext  |-f file_name] [-o filename] 
Options
	-a , todas las salidas se manejan en base 64. Por default usa bits crudos

Consideraciones:
	AES KEY SIZE ONLY 128, 192 o 256
::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "crypto.h"

void parseargs(int , char**);

int main(int argc, char **argv)
{
	initcryptofunctions();
    	parseargs(argc,argv);	
	return 0;
}

void parseargs(int argc,char **argv){
	unsigned char *buffin  = NULL;
	unsigned char *buffout = NULL;
	unsigned char *fileout = NULL;
	unsigned char *filein  = NULL;
	unsigned char *iphost  = NULL;
	int n;
 	int IN_MESG =0;	
	int BASE_64 =0;
	int ENCRYPT =0;
	int IN_FILE =0;
	int OUTFILE =0;
	char *msg="Usage:\nGeneracion de llaves publica y privada:\n\t \
		  ./securebits -k \nAdd host to well known hosts list\n\t \
		  ./securebits -kadd <ip> <local_path_to_public_rsa_key> \nCifrado\n\t \
		  ./securebits [options ] -e  [-h IPhost] [-in plaintext |-f file_name] [-o filename]\nDescifrado\n\t  \
		  ./securebits [options ] -d  [-f file_name] [-o filename]\nOptions\n\t   \
	          -a ,  Todas las salidas/entradas se manejan en base 64. Por default usa bits crudos\n";
	int i=1;
	/* Argumentos menores a los permitidos es decir solo sea llamado con un argumento*/
	if(argc<2)
		handleErrors(msg);
        /* BANDERAS 

	int ENCRYPT=0;
	int IN_MESG=0;	
	int IN_FILE=0;
	int OUTFILE=0;
	int BASE_64=0;
	
	/*Parseamos los parametros */
	i=1;
	while(argc>i){
		//Generacion de llaves  , secureb
		if(strcmp(argv[i],"-k")==0){
			if(i==1&&argc==2){
				keygen();
				exit(EXIT_SUCCESS);
			}
			else
				handleErrors(msg);
		}
		// agregamos llaves al llavero
		else if(strcmp(argv[i],"-kadd")==0){
			if(i==1&&argc==4){
				addtowellknownhosts(argv[2],argv[3]);
				exit(EXIT_SUCCESS);
			}
			else
				handleErrors(msg);
				
		}
		// No implementado aun
		else if(strcmp(argv[i],"-a")==0){
			BASE_64=1;
			if(argc<5)
				handleErrors(msg);
		}
		// cifrado y envio de paquetes
		else if(strcmp(argv[i],"-e")==0){
			ENCRYPT=1;
			if(argc<4)
				handleErrors(msg);
		}
		// Descofrado
		else if(strcmp(argv[i],"-d")==0){
			ENCRYPT=0;
			if(argc<4)
				handleErrors(msg);
		}
		else if(strcmp(argv[i],"-in")==0){
			
			IN_MESG=1;
			if(argc<4&&argc>(i+1))
				handleErrors(msg);
			i++;
			buffin=(unsigned char*)malloc(sizeof(unsigned char)*strlen(argv[i]));
			strcpy(buffin,argv[i]);
		}
		else if(strcmp(argv[i],"-f")==0){
			IN_FILE=1;
			if(argc<4&&argc>(i+1))
				handleErrors(msg);
			i++;
			filein=(char*)malloc(sizeof(char)*strlen(argv[i]));
			strcpy(filein,argv[i]);
		}
		else if(strcmp(argv[i],"-o")==0){
			OUTFILE=1;
			if(argc<6)
				handleErrors(msg);
			i++;			
			fileout=(char*)malloc(sizeof(char)*strlen(argv[i]));
			strcpy(fileout,argv[i]);
		}
		else if(strcmp(argv[i],"-h")==0){
			i++;
			iphost=(unsigned char*)malloc(sizeof(char)*strlen(argv[i]));	
			strcpy(iphost,argv[i]);
		}
		else
			handleErrors(msg);
		i++;
	}
	
	/*Banderas***********************************/
	if(ENCRYPT==1){
		if(IN_FILE==1)
		{
			n=readmsgfromfile(&buffin,filein);
			free(filein);
		}
		else
			n=strlen(buffin);
		packbits(buffin,n,buffout,fileout,iphost,BASE_64);
	}
	else{
		//La lectura del archivo se hara en unpackbits
		unpackbits(NULL,buffout,filein,fileout,BASE_64);
	}
	/***********************************************/
}
