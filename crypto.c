#include <openssl/evp.h>
#include <openssl/aes.h>

#define SERVER_CERT "server.pem"
#define RSA_PUB_SIZE RSA_size(crypto_ctx.pub_key)
#define RSA_PRIV_SIZE RSA_size(crypto_ctx.priv_key)


struct server_enc_ctx {
  EVP_CIPHER_CTX aes_ctx;
  RSA *pub_key;
  RSA *priv_key;
} crypto_ctx;

typedef struct server_enc_ctx server_enc_ctx_t;

int aes_init(unsigned char *key_data, int key_data_len, EVP_CIPHER_CTX *e_ctx, 
             EVP_CIPHER_CTX *d_ctx)
{
  int i, nrounds = 5;
  unsigned char key[32], iv[32];
  
  i = EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha1(), NULL, key_data, key_data_len, nrounds, key, iv);
  if (i != 32) {
    printf("Key size is %d bits - should be 256 bits\n", i);
    return -1;
  }

  EVP_CIPHER_CTX_init(e_ctx);
  EVP_EncryptInit_ex(e_ctx, EVP_aes_256_cbc(), NULL, key, iv);
  EVP_CIPHER_CTX_init(d_ctx);
  EVP_DecryptInit_ex(d_ctx, EVP_aes_256_cbc(), NULL, key, iv);

  return 0;
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
  FILE *cert_fp = NULL;

  cert_fp = fopen(SERVER_CERT, "rb");

  if(cert_fp == NULL)
    return STATUS_FAILURE;

  if(!PEM_read_RSA_PublicKey(cert_fp, &crypto_ctx.pub_key, NULL, NULL)) {
    fclose(cert_fp);
    return STATUS_FAILURE;
  }

  if(!PEM_read_RSA_PrivateKey(cert_fp, &crypto_ctx.priv_key, NULL, NULL)) {
    fclose(cert_fp);
    return STATUS_FAILURE;
  }

  fclose(cert_fp);
  return STATUS_SUCCESS;
}

int pub_encrypt(char *src, int len, char *dst) {
  return (RSA_public_encrypt(len, (unsigned char *)src, dst, crypto_ctx.pub_key, RSA_PKCS1_PADDING));
}

int priv_decrypt(char *src, int len, char *dst) {
  return (RSA_private_decrypt(len, (unsigned char *)src, dst, crypto_ctx.priv_key, RSA_PKCS1_PADDING));
}
