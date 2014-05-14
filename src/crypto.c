/*:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::

Compile:
gcc -o securebits securebits.c -lssl -lcrypto

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
#include <openssl/md5.h>
#include <sys/stat.h>
#include "crypto.h"
#include "base64.h"

int packbits(unsigned char * buffin, unsigned char * buffout, unsigned char * fileout,unsigned char *host,int base64){
	/*****************  KEY GEN *************************************************************/
	int i, nrounds = KEY_ROUNDS;
  	unsigned char *aes_key  = (unsigned char*)malloc(sizeof(unsigned char) * (AES_KEY_SIZE/8));
	unsigned char *iv       = (unsigned char*)malloc(sizeof(unsigned char) * (AES_KEY_SIZE/8));
	unsigned char *key_data = (unsigned char*)malloc(sizeof(unsigned char) * (AES_KEY_SIZE/8));
  	unsigned int salt[] = {12345, 54321};
	/*
   	* Gen key & IV for AES 256 CBC mode. A SHA1 digest is used to hash the supplied key material.
   	* nrounds is the number of times the we hash the material. More rounds are more secure but
   	* slower.
	* Generamos llave inicial, podriamos pedirsela al usuario  */
    	
	memset(key_data , 0, AES_KEY_SIZE/8);	
	if (!RAND_bytes(key_data, AES_KEY_SIZE/8))
			handleErrors("Funcion aleatoria RAND:bytes");
  	i = EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha1(), (unsigned char *)&salt, key_data, AES_KEY_SIZE/8, nrounds, aes_key, iv);
  	if (i != 32)
		handleErrors("Tamaño de llave invalido");
	
	/*******************************************************************************************/
	
	/********** INICIALIZAMOS EL CONTEXTO********************************************************/
	EVP_CIPHER_CTX ctx;	
	EVP_CIPHER_CTX_init(&ctx);
  	EVP_EncryptInit_ex(&ctx, EVP_aes_256_cbc(), NULL, aes_key, iv);
    	/********************************************************************************************/
	int len;
	len=strlen(buffin)+1;
        int c_len = len + AES_BLOCK_SIZE;
	int f_len = 0;
	unsigned char *ciphertext = (unsigned char*) malloc(c_len);

	/* allows reusing of 'e' for multiple encryption cycles */
	EVP_EncryptInit_ex(&ctx, NULL, NULL, NULL, NULL);
	/* update ciphertext, c_len is filled with the length of ciphertext generated,
	*len is the size of plaintext in bytes */
	EVP_EncryptUpdate(&ctx, ciphertext, &c_len, buffin, len);
	/* update ciphertext with the final remaining bytes */
	EVP_EncryptFinal_ex(&ctx, ciphertext+c_len, &f_len);
	len = c_len + f_len;
	/* Cifrado asimetrico********************/
	if(directoryexist(BASE_DIR)==0)
		keygen();
        // Aqui se debe indicar con que llave publica deseamos cifrar	
	RSA *public;
	if(host!=NULL)
		public  = getpublicRSAkey(host);
	else
		public  = getpublicRSAkey("localhost");
	char *encryptrsa = malloc(RSA_size(public));
	int   encryptrsa_len;

	if((encryptrsa_len = RSA_public_encrypt((AES_KEY_SIZE/8)+1, (unsigned char*)aes_key,(unsigned char*)encryptrsa,
	    public, RSA_PKCS1_OAEP_PADDING)) == -1)
		handleErrors("Bad RSA encryption");
	

	/* Salidas ******************************/
	//HEX
	printf("@HEX out\n");
	//printf("key (%d)=\n",AES_KEY_SIZE/8);
	//hex_print(aes_key,AES_KEY_SIZE/8);
	
	//printf("RSA encrypted key(%d)=\n",encryptrsa_len);	
	//hex_print(encryptrsa,encryptrsa_len);
	
	//printf("IV (%d)=\n",AES_KEY_SIZE/8);	
	//hex_print(iv,AES_KEY_SIZE/8);
	printf("Encrypted m(%d)=\n",len);
    	hex_print(ciphertext, len);

	//BASE 64
	if(base64==1){	
		int b64l;	
		int total_len=encryptrsa_len+AES_KEY_SIZE/8+len+4;
		unsigned char *total  = (unsigned char*)malloc(total_len);;
		int j=0;
		i=0;
		for(j=0;j<=encryptrsa_len;j++){
			total[i]=encryptrsa[j];
			i++;
		}
		//i++;
		//total[i]='\0';
		for(j=0;j<=AES_KEY_SIZE/8;j++){
			total[i]=iv[j];
			i++;
		}
		//i++;
		//total[i]='\0';
		for(j=0;j<=len;j++){
			total[i]=ciphertext[j];
			i++;
		}
		unsigned char *output      = cod_base64(total,total_len,&b64l);
		output[b64l]='\0';
		printf("Base64:\n*%s*\n", output);
		if(fileout!=NULL)
			write_ascii_tofile(fileout,output,b64l);
		
		free(output);
	
	}
	//FILE
	if(fileout!=NULL&&base64!=1)
	{	
		writectofile(fileout,encryptrsa,encryptrsa_len,iv,ciphertext,len);	
	}
	/* Fin salidas *********************/
	
	/* Clean up */	
	EVP_CIPHER_CTX_cleanup(&ctx);
	return len;
}
int unpackbits(unsigned char *buffin,unsigned char *buffout, unsigned  char *fname,unsigned char *fileout,int base64){
		
  	int i,j;
	//Buffers de in out del cifrado
	unsigned char *enc_out ;
	int enc_len;
	/************** GET MSG IV AND KEY *********************************************/
	unsigned char *iv      = (unsigned char*)malloc(sizeof(unsigned char) * (AES_KEY_SIZE/8));
	unsigned char *aes_key = (unsigned char*)malloc(sizeof(unsigned char) * (AES_KEY_SIZE/8));
	unsigned char  ckey[256];
	if(fname!=NULL){
		int n;
		// El texto que hemos leido se almacena en la variable buffin
		if(base64==1){
			n=sizeofcipherfile(fname);
			unsigned char *b64str=readmsgfromfile(fname);
			printf("Decoding from Base64(%d)...\n%s\n",n,b64str);
			n=dec_base64(b64str, &buffin);
			hex_print(buffin,n);
		}
		else
			n=readcipherfile(&buffin,fname);
		enc_len=n-(256+1)-((AES_KEY_SIZE/8)+1);
		enc_out = (unsigned char*)malloc(sizeof(unsigned char) * enc_len);
		printf("filelen=%d\n",n);
		// Por ahora lo tomaremos como un dogma de FE 256
		for(i=0;i<256;i++)
			ckey[i]=buffin[i];
		i++;
		j=0;
		// Recogemos el IV
		for(;i<(AES_KEY_SIZE/8)*9;i++){
			iv[j]=buffin[i];
			j++;
		}
		i=i+2;
		j=0;
		for(;i<n;i++){
			enc_out[j]=buffin[i];
			j++;
		}
		// Only for debugging purpose
		//printf("FROM FILE:\n");
		//printf("k(%d)=\n",256);
		//hex_print(ckey,256);
		
  		//printf("iv(%d)=\n",AES_KEY_SIZE/8);
		//hex_print(iv,AES_KEY_SIZE/8);
		
		//printf("c(%d)=\n",enc_len);
		//hex_print(enc_out,enc_len);
	}
	else
		handleErrors("Option -in not yet implemented for -d");
	/***********************************************************************/
	
	/** Descifrado asimetrico **********************************************/
	int decrypt_len=AES_KEY_SIZE/8;
	RSA *private=getprivateRSAkey();
	if(RSA_private_decrypt(256, (unsigned char*)ckey, (unsigned char*)aes_key,private, RSA_PKCS1_OAEP_PADDING) == -1) 
 		handleErrors("Bad RSA decryption");
	/***********************************************************************/
	EVP_CIPHER_CTX ctxc;	
	EVP_CIPHER_CTX_init(&ctxc);
  	EVP_DecryptInit_ex(&ctxc, EVP_aes_256_cbc(), NULL, aes_key, iv);
	
	/* because we have padding ON, we must allocate an extra cipher block size of memory */
	int *len;
	len=&enc_len;
  	int p_len = *len;
	int f_len = 0;  	
	unsigned char *plaintext = malloc(p_len + AES_BLOCK_SIZE);
  	EVP_DecryptInit_ex(&ctxc, NULL, NULL, NULL, NULL);
  	EVP_DecryptUpdate (&ctxc, plaintext, &p_len, enc_out, *len);
  	EVP_DecryptFinal_ex(&ctxc, plaintext+p_len, &f_len);
  	*len = p_len + f_len;
	plaintext[*len] = '\0';
	/**** SALIDAS ************************************************************/
	
    	printf("\ndecrypt(%d)=\n",*len);
    	hex_print(plaintext, *len);
	printf("%s\n",plaintext);
        //FILE
        if(fileout!=NULL)
                 write_ascii_tofile(fileout,plaintext,*len);

	/**************************************************************************/
	/* Clean up */
	return *len;
}
/* UTILS */
int keygen(void){
	printf("Generating a pair of RSA  keys... public.key & private.key\n...\n");
	RSA *keypair = RSA_generate_key(RSA_KEY_SIZE, PUB_EXP, NULL, NULL);

	BIO *pri = BIO_new(BIO_s_mem());
	BIO *pub = BIO_new(BIO_s_mem());

	PEM_write_bio_RSAPrivateKey(pri, keypair, NULL, NULL, 0, NULL, NULL);
	PEM_write_bio_RSAPublicKey(pub, keypair);

	size_t pri_len = BIO_pending(pri);
	size_t pub_len = BIO_pending(pub);

	char *pri_key = malloc(pri_len + 1);
	char *pub_key = malloc(pub_len + 1);

	BIO_read(pri, pri_key, pri_len);
	BIO_read(pub, pub_key, pub_len);

	pri_key[pri_len] = '\0';
	pub_key[pub_len] = '\0';
	/* van a un archivo */
	
	FILE *privf;
	FILE *pubf;
	if(directoryexist(BASE_DIR)==0)
		createdirestructure();
	
	if(NULL != (privf= fopen(PRIV_KEY_PATH, "w"))){	
	 	PEM_write_RSAPrivateKey(privf, keypair,NULL,NULL, 0,NULL,NULL);
	}
	else
		handleErrors("Generacion de llave privada private.key");
	
	if(NULL!= (pubf=fopen(PUB_KEY_PATH,"w"))){
		 PEM_write_RSAPublicKey(pubf,keypair);
	}
	else
		handleErrors("Generacion de llave publica public.key");
	fclose(privf);
	fclose(pubf);
	addtowellknownhosts("localhost",PUB_KEY_PATH);
	printf("\n%s\n%s\n", pri_key, pub_key);
	return 1;
}
int write_ascii_tofile(unsigned char *fileout,unsigned char *m,int size){
	FILE *file;
	file = fopen(fileout,"w");
	if(!file)
		handleErrors("El archivo de salida no se ha podido crear");
	fputs(m,file);
	fclose(file);
	return 1;
}
int writectofile(unsigned char *fileout,unsigned char *key,int keylen,unsigned char *iv,unsigned char *text,int sizec){
	FILE *file;
	file = fopen(fileout,"wb");
	int i;
	if(!file)
		handleErrors("El archivo de salida no se ha podido crear");
	struct recordsb *my_record=malloc(sizeof(struct recordsb));
	/*************************************************************************/
	my_record->key= (unsigned char*)malloc(sizeof(unsigned char)*keylen);
	for(i=0;i<keylen;i++)
		my_record->key[i]=key[i];
	/*************************************************************************/
	my_record->iv= (unsigned char*)malloc(sizeof(unsigned char)*AES_KEY_SIZE/8);
	for(i=0;i<AES_KEY_SIZE/8;i++)
		my_record->iv[i]=iv[i];
	/*************************************************************************/
	my_record->text= (unsigned char*)malloc(sizeof(unsigned char)*sizec);
	for(i=0;i<sizec;i++)
		my_record->text[i]=text[i];
	/*************************************************************************/	
	fwrite(my_record->key  , sizeof(char) , keylen+1, file);
	fwrite(my_record->iv   , sizeof(char) , AES_KEY_SIZE/8+1, file);
	fwrite(my_record->text , sizeof(char) , sizec, file);
	fclose(file);
	return 1;
}
int sizeofcipherfile(unsigned char *name){
	FILE *file;
	unsigned long fileLen;
	file=fopen(name ,"rb");
	if(!file)
		handleErrors("El archivo no se ha podido abrir");
	fseek(file,0,SEEK_END);
	fileLen=ftell(file);
	return fileLen;
}
//Leer texto oculto
int readcipherfile(unsigned char** buffin,char *name)
{
	FILE *file;
	unsigned long fileLen;
	//Open file
	file = fopen(name, "rb");
	if (!file)
		handleErrors("El archivo no se ha podido abrir");
	//Get file length

	fseek(file, 0, SEEK_END);
	fileLen=ftell(file);
	fseek(file, 0, SEEK_SET);
	//Allocate memory
	*buffin=(char *)malloc(fileLen+1);
	if (!*buffin){

                fclose(file);
		handleErrors("Memory error!:(");
	}

	//Read file contents into buffer
	fread(*buffin, fileLen, 1, file);
	fclose(file);
	return fileLen;
}
//Leer el texto claro
unsigned char* readmsgfromfile(char *name){
 	FILE *file;	
	unsigned long fileLen;
	unsigned char *buffin;
	//Open file
	file = fopen(name, "rb");
	if (!file)
		handleErrors("El archivo de entrada no se ha podido encontrar");
	//Get file length
	fseek(file, 0, SEEK_END);
	fileLen=ftell(file);
	fseek(file, 0, SEEK_SET);

	//Allocate memory
	buffin=(char *)malloc((fileLen+1)*sizeof(unsigned char));
	if (!buffin){
               	fclose(file);
		handleErrors("Memory error!:(");
	}

	//Read file contents into buffer
	fread(buffin, fileLen, 1, file);
	fclose(file);
	return buffin;
	
}
// HEX PRINT 
void hex_print(const void* pv, size_t len)
{
    const unsigned char * p = (const unsigned char*)pv;
    if (NULL == pv)
        printf("NULL");
    else
    {
        size_t i = 0;
        for (; i<len;++i){
		if(i%48==0&&i!=0)
			printf("\n");
            	printf("%02X ", *p++);
		
	}
    }
    printf("\n");
}
//Manejo de errores
void handleErrors(char *msg)
{
  printf("ERROR: %s \n",msg);
  ERR_print_errors_fp(stderr);
  exit(EXIT_FAILURE);
}
//Inicializacion de funciones
void initcryptofunctions(void){
	//
	ERR_load_crypto_strings();
  	OpenSSL_add_all_algorithms();
}
int directoryexist(char *pathname){

	struct stat info;
	if( stat( pathname, &info ) != 0 )
		return 0;
    		//printf( "cannot access %s\n", pathname );
	else if( info.st_mode & S_IFDIR )  // S_ISDIR() doesn't exist on my windows 
    		return 1;
		//printf( "%s is a directory\n", pathname );
	else
		return 0;
    		//printf( "%s is no directory\n", pathname );
}

int  createdirestructure(void){
	FILE *f;
	mkdir(BASE_DIR,0755);
	mkdir(KH_DIR,0755);
	f=fopen(KH_FILE_PATH,"w");
	if(f!=NULL)
		fclose(f);
}
RSA* getprivateRSAkey(void){
	FILE *fp;
	RSA* private;
 	if(NULL != (fp= fopen(PRIV_KEY_PATH, "r")) ){
          	private=PEM_read_RSAPrivateKey(fp,NULL,NULL,NULL);
          	if(private==NULL)
  			handleErrors("No pudimos cargar tu private RSA key");        
	}
         // This is working OK and privateKey is NOT NULL
	return private;
}
RSA* getpublicRSAkey(char *host){
	FILE *fp;
	RSA* public;
	unsigned char cs[MD5_DIGEST_LENGTH*2];
	char line [BUFF_SIZE];
	char hostf[BUFF_SIZE];
	int  FOUND=0;
    	FILE *wkh;

	wkh = fopen(KH_FILE_PATH,"r");
        if(!wkh)
		handleErrors("No he podido abrir el archivo de hosts\n");
	while ((fscanf(wkh, "%[^\n]", line)) != EOF )
   	{	
	        sscanf(line, "%[^',']",hostf);	
	    	sscanf(line, "%[^','],%[^',']",hostf,cs);	
		fgetc(wkh);
		
 		printf("%s %s\n",hostf,cs);
		if(strcmp(hostf,host)==0){

			FOUND=1;
			break;
		}

		
	}
        
	if(FOUND==0)
		handleErrors("No he encontrado una llave publica para cifrar ");
	//if(strcmp(hostf,"-e")==0){	
	/*
	RSA *PEM_read_RSA_PUBKEY(FILE *fp, RSA **x,
                                        pem_password_cb *cb, void *u);
	*/
	if(NULL!= (fp =fopen(cs,"r"))){
		public=PEM_read_RSAPublicKey(fp,NULL,NULL,NULL);
		if(public==NULL)
			handleErrors("No pudo cargarse la llave publica adecuada");
	}
	return public;
}
int addtowellknownhosts(char *host,char *ppath){
	unsigned char c[MD5_DIGEST_LENGTH];
	unsigned char cs[MD5_DIGEST_LENGTH*2];
    	int i;
    	FILE *file = fopen (ppath, "rb");
    	MD5_CTX mdContext;
   	int bytes;
    	unsigned char data[1024];
    	if (file == NULL) 
		handleErrors("No puedo encontrar la llave especificada");
	
    	MD5_Init (&mdContext);
    	while ((bytes = fread (data, 1, 1024, file)) != 0)
        	MD5_Update (&mdContext, data, bytes);
    	MD5_Final (c,&mdContext);
    	printf("Agregado llave publica %s\n",ppath);
	for(i = 0; i < MD5_DIGEST_LENGTH; i++) 
	{	
                 printf("%02x", c[i]);
		 sprintf(&cs[i*2], "%02x", (unsigned int)c[i]);
    		
	}
	printf (" %s\n", ppath);
    	fclose (file);
    	FILE *publica;
        publica = fopen(KH_FILE_PATH,"a");
        if(!publica)
		handleErrors("El archivo de salida no se ha podido crear");
        fprintf(publica,"%s,%s\n",host,ppath);
        fclose(file);
	return 0;
	
}
