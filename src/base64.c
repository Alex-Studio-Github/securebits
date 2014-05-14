#include <string.h> /* memset */
#include <unistd.h> /* close */
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include "base64.h"
int calcDecodeLength(const char* b64input) { //Calculates the length of a decoded base64 string
  int len = strlen(b64input);
  int padding = 0;
 
  if (b64input[len-1] == '=' && b64input[len-2] == '=') //last two chars are =
    padding = 2;
  else if (b64input[len-1] == '=') //last char is =
    padding = 1;
 
  return (int)len*0.75 - padding;
}
 
int dec_base64(char* b64message, unsigned char** buffer) { //Decodes a base64 encoded string
  BIO *bio, *b64;
  int decodeLen = calcDecodeLength(b64message),
      len = 0;
  *buffer = (char*)malloc(decodeLen+1);
  FILE* stream = fmemopen(b64message, strlen(b64message), "r");
 
  b64 = BIO_new(BIO_f_base64());
  bio = BIO_new_fp(stream, BIO_NOCLOSE);
  bio = BIO_push(b64, bio);
  BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL); //Do not use newlines to flush buffer
  len = BIO_read(bio, *buffer, strlen(b64message));
  //Can test here if len == decodeLen - if not, then return an error
  //(*buffer)[len] = '\0';
 
  BIO_free_all(bio);
  fclose(stream);
 
  return len; //success
}
unsigned char* cod_base64(unsigned char *data, int len, int *lenoutput )
{
	// bio is simply a class that wraps BIO* and it free the BIO in the destructor.

	BIO *b64 = BIO_new(BIO_f_base64()); // create BIO to perform base64
	BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);

	BIO *mem = BIO_new(BIO_s_mem()); // create BIO that holds the result

	// chain base64 with mem, so writing to b64 will encode base64 and write to mem.
	BIO_push(b64, mem);

	// write data
	int done = 0;
	int res = 0;
	while(!done)
	{
    		res = BIO_write(b64, data, len);

    		if(res <= 0) // if failed
    		{
        		if(BIO_should_retry(b64)){
            			continue;
        		}
        		else // encoding failed
       	 		{
            			/* Handle Error!!! */
        		}
    		}
    		else // success!
        		done = 1;
	}	

	BIO_flush(b64);

	// get a pointer to mem's data
	unsigned char* output;
	*lenoutput = BIO_get_mem_data(mem, &output);
	return output;
}
