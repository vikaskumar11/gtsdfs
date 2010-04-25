#include "common.h"
#include "msg.c"
 
#define FTPD "./ftpd/"

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
#define CERTFILE "server.pem"
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
    if (SSL_CTX_use_PrivateKey_file(ctx, CERTFILE, SSL_FILETYPE_PEM) != 1)
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

status_t handle_auth_req(msg_t *req, msg_t *resp) {

  resp->u.auth_resp.status = STATUS_SUCCESS;

  return STATUS_SUCCESS;
}

status_t handle_get_req(msg_t *req, msg_t *resp) {
  char *filename;
  struct stat stat_buf;
  char *file_data = NULL;
  int fd;

  resp->u.get_resp.status = STATUS_FAILURE;

  filename = malloc(strlen(FTPD) + req->u.get_req.filename_len + 1);

  strcpy(filename, FTPD);
  strcat(filename, req->u.get_req.filename);

  if(stat(filename, &stat_buf)) {
    perror("get: Unable to stat file\n");
    return STATUS_FAILURE;
  }

  fd = open(filename, O_RDONLY);

  if(fd <= 0) {
    printf("get: Unable to open files %s\n", filename);
    return STATUS_FAILURE;
  }

  file_data = malloc(stat_buf.st_size);
  if(read(fd, file_data, stat_buf.st_size) != stat_buf.st_size) {
    perror("get: Error reading from file\n");
    return STATUS_FAILURE;
  }

  resp->u.get_resp.filelen = stat_buf.st_size;
  resp->u.get_resp.data = file_data;
  resp->u.get_resp.status = STATUS_SUCCESS;

  close(fd);
  free(filename);

  return STATUS_SUCCESS;
}

status_t handle_put_req(msg_t *req, msg_t *resp) {
  char *filename;
  int fd;

  resp->u.put_resp.status = STATUS_FAILURE;

  filename = malloc(strlen(FTPD) + req->u.put_req.filename_len + 1);

  strcpy(filename, FTPD);
  strcat(filename, req->u.put_req.filename);

  fd = open(filename, O_CREAT|O_WRONLY);

  if(fd <= 0) {
    printf("put: Unable to open file %s\n", filename);
    return STATUS_FAILURE;
  }

  if(write(fd, req->u.put_req.data, req->u.put_req.file_len) 
      != req->u.put_req.file_len) {
    perror("put: Error writing to file\n");
    return STATUS_FAILURE;
  }

  resp->u.put_resp.status = STATUS_SUCCESS;
  close(fd);
  free(filename);

  return STATUS_SUCCESS;
}

status_t handle_server_message(SSL *ssl, msg_t *req, msg_t *resp) {

  if(STATUS_FAILURE == recv_message(ssl, req)) {
    return STATUS_FAILURE;
  }

  switch(req->hdr.type) {
    case REQ_AUTH:
      resp->hdr.type = RSP_AUTH;
      handle_auth_req(req, resp);
      break;
    case REQ_GET:
      resp->hdr.type = RSP_GET;
      handle_get_req(req, resp);
      break;
    case REQ_PUT:
      resp->hdr.type = RSP_PUT;
      handle_get_req(req, resp);
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

int do_server_loop(SSL *ssl)
{
    msg_t req, resp;

    printf("do_server_loop\n");

    do
    {
      memset(&req, 0, sizeof(msg_t));
      memset(&resp, 0, sizeof(msg_t));

      if(STATUS_FAILURE == receive_payload(ssl, &req)) {
        perror("Socket Error: Thread returning\n");
        break;
      }

      handle_server_message(ssl, &req, &resp);
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
    long err;
 
    pthread_detach(pthread_self());

    if (SSL_accept(ssl) <= 0)
        handle_error("Error accepting SSL connection");
    if ((err = post_connection_check(ssl, CLIENT)) != X509_V_OK)
    {
        fprintf(stderr, "-Error: peer certificate: %s\n",
                X509_verify_cert_error_string(err));
        handle_error("Error checking SSL object after connection");
    }
    fprintf(stderr, "SSL Connection opened\n");
    if (do_server_loop(ssl))
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
 
    ctx = setup_server_ctx(  );
 
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

