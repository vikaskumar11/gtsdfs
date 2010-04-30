#include "common.h"
#include "msg.c"
#include "crypto.c"

extern char *session_owner;
extern int server;

struct file_meta {
  uint32_t owner_len;
  char *owner;
  char *key;
  char *iv;
     uint8_t host_len;     
     char *host;
     uint8_t rights;
     uint32_t delegate;
};

typedef struct file_meta file_meta_t;

#define FTPD "./ftpd/"
#define FILE_META_SIZE (4+RSA_PUB_SIZE+strlen(owner))

DH *dh512 = NULL;
DH *dh1024 = NULL;

void init_dhparams(void)
{
    BIO *bio;

    bio = BIO_new_file("dh512.pem", "r");
    if (!bio)
        handle_error("Error opening file dh512.pem");
    dh512 = PEM_read_bio_DHparams(bio, NULL, NULL, NULL);
    if (!dh512)
        handle_error("Error reading DH parameters from dh512.pem");
    BIO_free(bio);

    bio = BIO_new_file("dh1024.pem", "r");
    if (!bio)
        handle_error("Error opening file dh1024.pem");
    dh1024 = PEM_read_bio_DHparams(bio, NULL, NULL, NULL);
    if (!dh1024)
        handle_error("Error reading DH parameters from dh1024.pem");
    BIO_free(bio);
}

DH *tmp_dh_callback(SSL *ssl, int is_export, int keylength)
{
    DH *ret;

    if (!dh512 || !dh1024)
        init_dhparams(  );

    switch (keylength)
    {
        case 512:
            ret = dh512;
            break;
        case 1024:
        default: /* generating DH params is too costly to do on the fly */
            ret = dh1024;
            break;
    }
    return ret;
}

#define CIPHER_LIST "ALL:!ADH:!LOW:!EXP:!MD5:@STRENGTH"
#define CAFILE "rootcert.pem"
#define CADIR NULL
#define CERTFILE "servercert.pem"
#define KEYFILE "serverkey.pem"

SSL_CTX *setup_server_ctx(void)
{
    SSL_CTX *ctx;
 
    ctx = SSL_CTX_new(SSLv23_method(  ));
    if (SSL_CTX_load_verify_locations(ctx, CAFILE, CADIR) != 1)
        handle_error("Error loading CA file and/or directory");
    if (SSL_CTX_set_default_verify_paths(ctx) != 1)
        handle_error("Error loading default CA file and/or directory");
    if (SSL_CTX_use_certificate_chain_file(ctx, CERTFILE) != 1)
        handle_error("Error loading certificate from file");
    if (SSL_CTX_use_PrivateKey_file(ctx, KEYFILE, SSL_FILETYPE_PEM) != 1)
        handle_error("Error loading private key from file");
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER|SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
                       verify_callback);
    SSL_CTX_set_verify_depth(ctx, 4);
    SSL_CTX_set_options(ctx, SSL_OP_ALL | SSL_OP_NO_SSLv2 |
                             SSL_OP_SINGLE_DH_USE);
    SSL_CTX_set_tmp_dh_callback(ctx, tmp_dh_callback);
    if (SSL_CTX_set_cipher_list(ctx, CIPHER_LIST) != 1)
        handle_error("Error setting cipher list (no valid ciphers)");
    return ctx;
}

status_t is_delegated(char *filename, char *owner, int action)
{
     FILE* fp = NULL;
     struct stat stat_buf;
     int idx = 0, rt, fd, rights, propagate, time, t, host_len;
     struct timeval t_now, t_delg, res;
     char * meta_data, host[512];

     if(stat(filename, &stat_buf)) {
	  perror("get: Unable to stat file\n");
	  return STATUS_FAILURE;
     }  
     
  fd = open(filename, O_RDONLY);

  if(fd <= 0) {
    printf("get: Unable to open files %s\n", filename);
    return STATUS_FAILURE;
  }

  meta_data = malloc(stat_buf.st_size);
  if(read(fd, meta_data, stat_buf.st_size) != stat_buf.st_size) {
    perror("get: Error reading from file\n");
    return STATUS_FAILURE;
  }
  close(fd);

  idx += 4;
  idx += *((uint32_t *) meta_data);
  idx += RSA_PUB_SIZE;
  free(meta_data);

  fp = fopen(filename, "r");
  if(NULL == fp)
  {
       perror("fopen");
       return STATUS_FAILURE;
  }
  
  fseek(fp, idx, SEEK_SET);

  do 
  {
       /*rt = fscanf(fp, "%d %s %d %d %d %d\n", &host_len, host, &rights, &t, &time, &propagate);
       if(rt == EOF)
	    break;*/

       sscanf(meta_data+idx, "%d%s%d%d%d%d", &host_len, host, &rights, &t, &time, &propagate);

       printf("%s %d %d %d %d\n", host, rights, t, time, propagate);
       if(0 == strcmp(host, owner))
       {
	    if((rights & action) == action)
	    {
		 gettimeofday(&t_now, NULL);
		 t_delg.tv_sec = t;
		 timersub(&t_now, &t_delg, &res);

		 if(res.tv_sec <= time)
		      return STATUS_SUCCESS;
	    }
       }

       break;
  }while(1);
  
  fclose(fp);

  return STATUS_FAILURE;   
}

status_t handle_auth_req(char *owner, msg_t *req, msg_t *resp) {

  resp->u.auth_resp.status = STATUS_SUCCESS;

  return STATUS_SUCCESS;
}

status_t handle_get_req(char *owner, msg_t *req, msg_t *resp) {
  char *filename, *plaintext;
  struct stat stat_buf;
  char *file_data = NULL, *meta_data = NULL;
  char enc_key[RSA_PUB_SIZE], sym_key[RSA_PUB_SIZE];
  int fd, idx = 0, len = 0, flen = 0;
  file_meta_t file_meta;

  resp->u.get_resp.status = STATUS_FAILURE;
  memset(&file_meta, 0, sizeof(file_meta_t));

  flen = strlen(FTPD) + req->u.get_req.filename_len;
  filename = malloc(flen + 6);

  strcpy(filename, FTPD);
  strcat(filename, req->u.get_req.filename);
  strcat(filename, ".m");

  if(stat(filename, &stat_buf)) {
    perror("get: Unable to stat file\n");
    return STATUS_FAILURE;
  }

  fd = open(filename, O_RDONLY);

  if(fd <= 0) {
    printf("get: Unable to open files %s\n", filename);
    return STATUS_FAILURE;
  }

  meta_data = malloc(stat_buf.st_size);
  if(read(fd, meta_data, stat_buf.st_size) != stat_buf.st_size) {
    perror("get: Error reading from file\n");
    return STATUS_FAILURE;
  }

  close(fd);

  file_meta.owner_len = *((uint32_t *) meta_data);
  idx += 4;

  file_meta.owner = malloc(file_meta.owner_len+1);
  memcpy(file_meta.owner, meta_data+idx, file_meta.owner_len);
  file_meta.owner[file_meta.owner_len] = '\0';
  idx += file_meta.owner_len;

  if(strcmp(file_meta.owner, owner)) {
    printf("User %s trying to access file owned by %s. Denied\n",
		        owner, file_meta.owner);

      if(STATUS_FAILURE == is_delegated(filename, owner, DELG_GET))
	   return STATUS_FAILURE;
    goto fail;
  }

  memcpy(enc_key, meta_data+idx, RSA_PUB_SIZE);
  if(priv_decrypt(enc_key, RSA_PUB_SIZE, sym_key) != 64) {
    perror("get: RSA decrypt error\n");
    goto fail; 

  }

  file_meta.key = sym_key;
  file_meta.iv = sym_key + 32;

  filename[flen] = '\0';
  fd = open(filename, O_RDONLY);

  memset(&stat_buf, 0, sizeof(stat_buf));
  if(stat(filename, &stat_buf)) {
    perror("get: Unable to stat file\n");
    return STATUS_FAILURE;
  }

  if(fd <= 0) {
    printf("get: Unable to open files %s\n", filename);
    goto fail;
  }

  len = stat_buf.st_size;
  file_data = malloc(len);
  if(read(fd, file_data, len) != len) {
    perror("get: Error reading from file\n");
    free(file_data);
    goto fail;
  }

  close(fd);

  aes_dec_init((unsigned char *)file_meta.key, (unsigned char *)file_meta.iv);
    
  plaintext = aes_decrypt(&crypto_ctx.aes_ctx, file_data, &len);

  resp->u.get_resp.filelen = len;
  resp->u.get_resp.data = plaintext;
  resp->u.get_resp.status = STATUS_SUCCESS;

  aes_cleanup(&crypto_ctx.aes_ctx);
  free(filename);
  free(meta_data);
  free(file_meta.owner);
  free(file_data);

  return STATUS_SUCCESS;

fail:
  free(filename);
  free(meta_data);
  free(file_meta.owner);

  return STATUS_FAILURE;
}

status_t handle_put_req(char *owner, msg_t *req, msg_t *resp) {
  char *filename, *metadata;
  char key[64];
  char *iv = key + 32;
  char *enc_file = NULL, *enc_key;
  int fd, len = 0, idx = 0, file_len = 0;
  struct stat stat_buf;


  resp->u.put_resp.status = STATUS_FAILURE;

  file_len = strlen(FTPD) + req->u.put_req.filename_len;
  filename = malloc(file_len + 6);

  strcpy(filename, FTPD);
  strcat(filename, req->u.put_req.filename);
  strcat(filename, ".m");

  if(!stat(filename, &stat_buf)) {
    char tmpbuf[128];
    uint32_t owner_len = 0;

    fd = open(filename, O_RDONLY);
    if(fd <= 0) {
      printf("get: Unable to open files %s\n", filename);
      free(filename);
      return STATUS_FAILURE;
    }

    if(read(fd, tmpbuf, 4) != 4) {
      perror("put: Error reading from file\n");
      return STATUS_FAILURE;
    }

    owner_len = *(uint32_t *)(tmpbuf);
    if(owner_len > 128) {
      perror("Owner length too long in meta file\n");
      return STATUS_FAILURE;
    }
  
    if(read(fd, tmpbuf, owner_len) != owner_len) {
      perror("put: Error reading from file\n");
      return STATUS_FAILURE;
    }

    tmpbuf[owner_len] = '\0';

    if(strcmp(tmpbuf, owner)) {
      printf("User %s trying to overwrite file owned by %s. Denied\n",
          owner, tmpbuf);
      if(STATUS_FAILURE == is_delegated(filename, owner, DELG_PUT))
      {
	   free(filename);
	   return STATUS_FAILURE;
      }
    }

    close(fd);
  }

  filename[file_len] = '\0';

  aes_init((unsigned char *)req->u.put_req.data, req->u.put_req.file_len, (unsigned char *)key, (unsigned char *)iv);
  aes_enc_init((unsigned char *)key, (unsigned char *)iv);

  len = req->u.put_req.file_len;
  enc_file = aes_encrypt(&crypto_ctx.aes_ctx, req->u.put_req.data, &len);

  enc_key = malloc(RSA_PUB_SIZE);
  if(pub_encrypt(key, 64, enc_key) <= 0) {
     aes_cleanup(&crypto_ctx.aes_ctx);
     free(filename);
     free(enc_file);
     return STATUS_FAILURE;
  }

  fd = open(filename, O_CREAT|O_WRONLY, 0777);

  if(fd <= 0) {
    printf("put: Unable to open file %s\n", filename);
    return STATUS_FAILURE;
  }

  if(write(fd, enc_file, len) != len) {
    perror("put: Error writing to file\n");
    return STATUS_FAILURE;
  }

  close(fd);

  strcat(filename, ".m");
  fd = open(filename, O_CREAT|O_WRONLY, 0777);

  if(fd <= 0) {
    printf("put: Unable to open file %s\n", filename);
    return STATUS_FAILURE;
  }

  metadata = malloc(FILE_META_SIZE);

  /* owner len*/
  *((uint32_t *) metadata) = strlen(owner);
  idx += 4;

  /*owner*/
  memcpy(metadata+idx, owner, strlen(owner));
  idx += strlen(owner);

  /* encrypted key */
  memcpy(metadata+idx, enc_key, RSA_PUB_SIZE);
  idx += RSA_PUB_SIZE;

  assert(idx <= FILE_META_SIZE);

  if(write(fd, metadata, idx) != idx) {
    perror("put: Error writing to file\n");
    return STATUS_FAILURE;
  }

  resp->u.put_resp.status = STATUS_SUCCESS;

  close(fd);
  aes_cleanup(&crypto_ctx.aes_ctx); 
  free(filename);
  free(enc_file);
  free(metadata);
  free(enc_key);

  return STATUS_SUCCESS;
}


status_t handle_delg_req(char *owner, msg_t *req, msg_t *resp) {
  char *filename;
  struct stat stat_buf;
  file_meta_t file_meta;
  FILE *fp = NULL;
  struct timeval t;
  int flen, fd, owner_len;
  char tmpbuf[128]= "";


  resp->u.delg_resp.status = STATUS_FAILURE;
  memset(&file_meta, 0, sizeof(file_meta_t));

  flen = strlen(FTPD) + req->u.delg_req.filename_len;
  filename = malloc(flen + 6);

  strcpy(filename, FTPD);
  strcat(filename, req->u.get_req.filename);
  strcat(filename, ".m");

  if(stat(filename, &stat_buf)) {
    perror("get: Unable to stat file\n");
    return STATUS_FAILURE;
  }

    fd = open(filename, O_RDONLY);
    if(fd <= 0) {
      printf("get: Unable to open files %s\n", filename);
      free(filename);
      return STATUS_FAILURE;
    }

    if(read(fd, tmpbuf, 4) != 4) {
      perror("put: Error reading from file\n");
      return STATUS_FAILURE;
    }

    owner_len = *(uint32_t *)(tmpbuf);
    if(owner_len > 128) {
      perror("Owner length too long in meta file\n");
      return STATUS_FAILURE;
    }
  
    if(read(fd, tmpbuf, owner_len) != owner_len) {
      perror("put: Error reading from file\n");
      return STATUS_FAILURE;
    }

    tmpbuf[owner_len] = '\0';

    if(strcmp(tmpbuf, owner)) {
      printf("User %s trying to delegate file owned by %s. Denied\n",
          owner, tmpbuf);
      if(STATUS_FAILURE == is_delegated(filename, owner, DELG_DELG | req->u.delg_req.rights))
      {
	   free(filename);
	   return STATUS_FAILURE;
      }
    }

  fp = fopen(filename, "a");

  if(fp == NULL) {
    printf("get: Unable to open files %s\n", filename);
    return STATUS_FAILURE;
  }

  timerclear(&t);
  if(0 != gettimeofday(&t,NULL))
       perror("gettimeofday");

  fprintf(fp, "%d%s%d%d%d%d", req->u.delg_req.host_len, req->u.delg_req.host, req->u.delg_req.rights, (int)t.tv_sec, req->u.delg_req.time, req->u.delg_req.propagate);

  fclose(fp);
}

status_t handle_server_message(SSL *ssl, char *owner, msg_t *req, msg_t *resp) {

  switch(req->hdr.type) {
    case REQ_AUTH:
      resp->hdr.type = RSP_AUTH;
      handle_auth_req(owner, req, resp);
      break;
    case REQ_GET:
      resp->hdr.type = RSP_GET;
      handle_get_req(owner, req, resp);
      break;
    case REQ_PUT:
      resp->hdr.type = RSP_PUT;
      handle_put_req(owner, req, resp);
      break;
    case REQ_DELG:
      resp->hdr.type = RSP_DELG;
      handle_delg_req(owner, req, resp);
      break;
  }

  return STATUS_SUCCESS;

}

void free_message(msg_t *msg) {

  switch(msg->hdr.type) {
    case RSP_GET:
      if(msg->u.get_resp.data) 
        free(msg->u.get_resp.data);
      break;
    case REQ_GET:
      if(msg->u.get_req.filename)
        free(msg->u.get_req.filename);
      break;
    case RSP_PUT:
      break;
    case REQ_PUT:
      if(msg->u.put_req.filename)
        free(msg->u.get_req.filename);
      if(msg->u.put_req.data)
        free(msg->u.put_req.data);
      break;
  }

  return;
}

int do_server_loop(SSL *ssl, char *owner)
{
    msg_t req, resp;

    printf("do_server_loop\n");

    do
    {
      memset(&req, 0, sizeof(msg_t));
      memset(&resp, 0, sizeof(msg_t));

      if(STATUS_FAILURE == recv_message(ssl, &req)) {
        perror("Socket Error: Thread returning\n");
        break;
      }

      handle_server_message(ssl, owner, &req, &resp);
      send_message(ssl, &resp);

      free_message(&req);
      free_message(&resp);
      free(req.pkt->buf);
      free(req.pkt);
    }
    while (1);
    return (SSL_get_shutdown(ssl) & SSL_RECEIVED_SHUTDOWN) ? 1 : 0;
}
  
void server_thread(void *arg)
{
    SSL *ssl = (SSL *)arg;
    char *owner;
    long err;
 
    pthread_detach(pthread_self());

    owner = (char *) malloc(128);

    if(owner == NULL)
      handle_error("Unable to allocate memory\n");

    session_owner = owner;
    if (SSL_accept(ssl) <= 0)
        handle_error("Error accepting SSL connection");
    if ((err = post_connection_check(ssl, CLIENT)) != X509_V_OK)
    {
        fprintf(stderr, "-Error: peer certificate: %s\n",
                X509_verify_cert_error_string(err));
        handle_error("Error checking SSL object after connection");
    }
    session_owner = NULL;
    fprintf(stderr, "SSL Connection opened\n");
    if (do_server_loop(ssl, owner))
        SSL_shutdown(ssl);
    else
        SSL_clear(ssl);
    fprintf(stderr, "SSL Connection closed\n");
    SSL_free(ssl);
    ERR_remove_state(0);
}
 
int main(int argc, char *argv[])
{
    BIO     *acc, *client;
    SSL     *ssl;
    SSL_CTX *ctx;
    THREAD_TYPE tid;

    init_OpenSSL(  );
    seed_prng(  );
    server = 1;

    ctx = setup_server_ctx(  );

    if(server_crypto_init() != STATUS_SUCCESS) {
       handle_error("Error initializing server RSA");       
    }
 
    acc = BIO_new_accept(PORT);
    if (!acc)
        handle_error("Error creating server socket");
 
    if (BIO_do_accept(acc) <= 0)
        handle_error("Error binding server socket");
 
    for (;;)
    {
        if (BIO_do_accept(acc) <= 0)
            handle_error("Error accepting connection");
 
        client = BIO_pop(acc);
        if (!(ssl = SSL_new(ctx)))
        handle_error ("Error creating SSL context");
        SSL_set_accept_state(ssl);
        SSL_set_bio(ssl, client, client);
        THREAD_CREATE(tid, (void *)server_thread, ssl);
    }
 
    SSL_CTX_free(ctx);
    BIO_free(acc);
    return 0;
}

