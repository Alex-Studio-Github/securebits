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

#define AES_KEY_SIZE 256
#define KEY_ROUNDS   10
#define RSA_KEY_SIZE 2048
#define PUB_EXP	     65537
#define BASE_DIR      "secureb"
#define PRIV_KEY_PATH "./secureb/private.key"
#define PUB_KEY_PATH  "./secureb/public.key"
#define KH_DIR	      "./secureb/hosts"
#define KH_FILE_PATH  "./secureb/hosts/knownhosts"
#define BUFF_SIZE    1024
//ESTRUCTURAS
struct recordsb
{	
	unsigned char *key ;
	unsigned char *iv  ;
	unsigned char *text;
};


/* UTILS                  */
void hex_print(const void*, size_t);
void parseargs(int,char**);
void handleErrors(char*);
void initcryptofunctions(void);
int  keygen(void);
int  addtowellknownhosts(char*,char*);
RSA* getprivateRSAkey(void);
RSA* getpublicRSAkey(char*);
int 		 sizeofcipherfile(unsigned char*);
int              readcipherfile(unsigned char**,char*);
unsigned char *  readmsgfromfile(char*);
int  write_ascii_tofile(unsigned char*,unsigned char*,int);
int  writectofile(unsigned char*,unsigned char*,int,unsigned char*,unsigned char*,int);
int  directoryexist(char*);
int  createdirestructure(void);

/* CORE                  
packbits recibe el buffer a cifrar, buffer descifrado , archivo de entrada y archivo
de salida.

unpackbits recibe el buffer a descifrar , buffer cifrado , archivo de entrada y
archivo de salida.

NOTA:
*/
int packbits  (unsigned char *, unsigned char *, unsigned char *, unsigned char *,int);
int unpackbits(unsigned char *, unsigned char *, unsigned char *, unsigned char *,int);
