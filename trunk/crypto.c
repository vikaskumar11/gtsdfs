#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <string.h>

#define SERVER_CERT "servercert.pem"
#define KEYFILE "serverkey.pem"
#define RSA_PUB_SIZE RSA_size(crypto_ctx.pub_key)
#define RSA_PRIV_SIZE RSA_size(crypto_ctx.priv_key)

struct server_enc_ctx {
  EVP_CIPHER_CTX aes_ctx;
  RSA *pub_key;
  RSA *priv_key;
  EVP_PKEY *pkey; 
} crypto_ctx;

typedef struct server_enc_ctx server_enc_ctx_t;

int aes_init(unsigned char *key_data, int key_data_len, unsigned char *key_out, unsigned char *iv_out)
{
  int i, nrounds = 5;
  //unsigned char key[32], iv[32];
  
  i = EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha1(), NULL, key_data, key_data_len, nrounds, key_out, iv_out);
  if (i != 32) {
    printf("Key size is %d bits - should be 256 bits\n", i);
    return -1;
  }

  return 0;
}

void aes_enc_init(unsigned char *key, unsigned char *iv) {
  EVP_CIPHER_CTX_init(&crypto_ctx.aes_ctx);
  EVP_EncryptInit_ex(&crypto_ctx.aes_ctx, EVP_aes_256_cbc(), NULL, key, iv);
}

void aes_dec_init(unsigned char *key, unsigned char *iv) {
  EVP_CIPHER_CTX_init(&crypto_ctx.aes_ctx);
  EVP_DecryptInit_ex(&crypto_ctx.aes_ctx, EVP_aes_256_cbc(), NULL, key, iv);
}

unsigned char *aes_encrypt(EVP_CIPHER_CTX *e, unsigned char *plaintext, int *len)
{
  int c_len = *len + AES_BLOCK_SIZE, f_len = 0;
  unsigned char *ciphertext = malloc(c_len);

  EVP_EncryptInit_ex(e, NULL, NULL, NULL, NULL);

  EVP_EncryptUpdate(e, ciphertext, &c_len, plaintext, *len);

  EVP_EncryptFinal_ex(e, ciphertext+c_len, &f_len);

  *len = c_len + f_len;
  return ciphertext;
}

unsigned char *aes_decrypt(EVP_CIPHER_CTX *e, unsigned char *ciphertext, int *len)
{
  int p_len = *len, f_len = 0;
  unsigned char *plaintext = malloc(p_len);
  
  EVP_DecryptInit_ex(e, NULL, NULL, NULL, NULL);
  EVP_DecryptUpdate(e, plaintext, &p_len, ciphertext, *len);
  EVP_DecryptFinal_ex(e, plaintext+p_len, &f_len);

  *len = p_len + f_len;
  return plaintext;
}

void inline aes_cleanup(EVP_CIPHER_CTX *ctx) {
  EVP_CIPHER_CTX_cleanup(ctx);
}

status_t server_crypto_init() {
  FILE *cert_fp = NULL, *fp = NULL;
  X509 *x509 = NULL;

  memset(&crypto_ctx, 0, sizeof(crypto_ctx));

  OpenSSL_add_all_algorithms();
  cert_fp = fopen(SERVER_CERT, "rb");

  if(cert_fp == NULL)
    return STATUS_FAILURE;

  x509= PEM_read_X509(cert_fp, NULL, NULL, NULL);
  if(x509 == NULL) {
    printf("Cant read x509\n");
    return STATUS_FAILURE;
  }

  crypto_ctx.pkey = X509_get_pubkey(x509);
  if(crypto_ctx.pkey == NULL) {
     printf("Cant get x509 pubkey\n");     
     return STATUS_FAILURE;
  }

  crypto_ctx.pub_key = EVP_PKEY_get1_RSA(crypto_ctx.pkey);

  if(crypto_ctx.pub_key == NULL) {
    printf("Error getting rsa key\n");
    return STATUS_FAILURE;
  }

  fp = fopen(KEYFILE, "rb");
  
  if(fp == NULL) {
   printf("cannot open file\n");
   return STATUS_FAILURE;
  }

  if((crypto_ctx.priv_key = PEM_read_RSAPrivateKey(fp, NULL, NULL, NULL)) == NULL) { 
    ERR_print_errors_fp(stderr);
    fclose(cert_fp);
    return STATUS_FAILURE;
  }

  fclose(cert_fp);
  fclose(fp);

  return STATUS_SUCCESS;
}

int pub_encrypt(char *src, int len, char *dst) {
  return (RSA_public_encrypt(len, (unsigned char *)src, (unsigned char *)dst, crypto_ctx.pub_key, RSA_PKCS1_PADDING));
}

int priv_decrypt(char *src, int len, char *dst) {
  return (RSA_private_decrypt(len, (unsigned char *)src, (unsigned char *)dst, crypto_ctx.priv_key, RSA_PKCS1_PADDING));
}

#if 0
int main() {
  char buf[32];
  char key[32], iv[32];
  char *dst;
  int len = 32;
  char *ciph;

  /*(server_crypto_init() == STATUS_SUCCESS) {
    printf("RSA Size: %d\n", RSA_PUB_SIZE);
  }		    

  dst = malloc(RSA_PUB_SIZE);
  memset(dst, 0, 128);*/
  memset(buf, 2, sizeof(buf));
/*  printf("Encrypting data: %d\n", pub_encrypt(buf, 32, dst));

  memset(buf, 0, sizeof(buf));
  printf("Decrypting: %d\n", priv_decrypt(dst, RSA_PUB_SIZE, buf));
  ERR_print_errors_fp(stderr);	  */

  aes_init("venkat", 6, key, iv);
  aes_enc_init(key, iv);
  ciph = aes_encrypt(&crypto_ctx.aes_ctx, buf, &len);

  aes_cleanup(&crypto_ctx.aes_ctx);
  aes_dec_init(key, iv);
  ciph = aes_decrypt(&crypto_ctx.aes_ctx, ciph, &len);

  return 0;
}
#endif
