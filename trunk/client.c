#include "common.h"
#include "msg.c"
 
#define CIPHER_LIST "ALL:!ADH:!LOW:!EXP:!MD5:@STRENGTH"
#define CAFILE "rootcert.pem"
#define CADIR NULL
#define CERTFILE "clientcert.pem"
#define KEYFILE "clientkey.pem"

SSL_CTX *setup_client_ctx(void)
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
     SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, verify_callback);
     SSL_CTX_set_verify_depth(ctx, 4);
     SSL_CTX_set_options(ctx, SSL_OP_ALL|SSL_OP_NO_SSLv2);
     if (SSL_CTX_set_cipher_list(ctx, CIPHER_LIST) != 1)
	  handle_error("Error setting cipher list (no valid ciphers)");
     return ctx;
}

status_t handle_get_resp( msg_t *req, msg_t *resp) {

     FILE *fd;

     if(STATUS_FAILURE == resp->u.get_resp.status)
	  return STATUS_FAILURE;

     fd = fopen(req->u.get_req.filename, "w");
     if(NULL == fd)
     {
	  perror("fopen");
	  return STATUS_FAILURE;
     }

     if(resp->u.get_resp.filelen != fwrite(resp->u.get_resp.data, 1, resp->u.get_resp.filelen, fd))
     {
	  perror("fwrite");
	  return STATUS_FAILURE;
     }     
 
     fclose(fd);

     return STATUS_SUCCESS;
}
 
status_t handle_put_resp( msg_t *req, msg_t *resp) {
     
     if(STATUS_FAILURE == resp->u.put_resp.status)
	  return STATUS_FAILURE;

     return STATUS_SUCCESS;
}

status_t handle_delg_resp( msg_t *req, msg_t *resp) {
     
     if(STATUS_FAILURE == resp->u.delg_resp.status)
	  return STATUS_FAILURE;

     return STATUS_SUCCESS;
}

status_t handle_client_message(SSL *ssl, msg_t *req, msg_t *resp) {

     if(STATUS_FAILURE == recv_message(ssl, resp)) {
	  return STATUS_FAILURE;
     }

     switch(resp->hdr.type) {
     case RSP_AUTH:
	  //resp->hdr.type = RSP_AUTH;
	  //handle_auth_res(resp);
	  break;
     case RSP_GET:
	  handle_get_resp(req, resp);
	  break;
     case RSP_PUT:
	  handle_put_resp(req, resp);
	  break;
     case RSP_DELG:
	  handle_delg_resp(req, resp);
	  break;

     }

     return STATUS_SUCCESS;

}

int get(SSL *ssl, char *fname, char *uid)
{
     msg_t req, resp;
	
     memset(&req, 0, sizeof(msg_t));
     memset(&resp, 0, sizeof(msg_t));
     req.hdr.type = REQ_GET;
     req.u.get_req.del_req = 0;
     req.u.get_req.filename_len = strlen(fname);
     req.u.get_req.num_tokens = 0;
     req.u.get_req.filename = fname;


     if(STATUS_FAILURE == send_message(ssl, &req))
     {
	  perror("send req failed\n");
	  return 0;
     }

     return handle_client_message(ssl, &req, &resp);
}


int put(SSL *ssl, char *fname, char *uid)
{
     struct stat buffer;
     int fd;	
     msg_t req, res;

     memset(&req, 0, sizeof(msg_t));
     memset(&res, 0, sizeof(msg_t));
     req.hdr.type = REQ_PUT;
     req.u.put_req.del_req = 0;
     req.u.put_req.filename = fname;
     req.u.put_req.filename_len = strlen(fname);
     req.u.put_req.num_tokens = 0;


     fd= open(fname, O_RDWR);
     if(-1 == fstat(fd, &buffer))
     {
	  perror("fstat");
	  return STATUS_FAILURE;
     }

     req.u.put_req.file_len = buffer.st_size;

     req.u.put_req.data = malloc(buffer.st_size);
     assert(NULL != req.u.put_req.data);

     if(read(fd, req.u.put_req.data, buffer.st_size) != buffer.st_size) {
	  perror("get: Error reading from file\n");
	  return STATUS_FAILURE;
     }

     if(STATUS_FAILURE == send_message(ssl, &req))
     {
	  perror("send req failed\n");
	  return 0;
     }

     return handle_client_message(ssl, &req, &res);
}

int delegate(SSL *ssl, char *fname, char *uid, char *rights, char *host, char *time, char *prop )
{
     msg_t req, res;
     int propagate;

     memset(&req, 0, sizeof(msg_t));
     memset(&res, 0, sizeof(msg_t));
     req.hdr.type = REQ_DELG;
     req.u.delg_req.del_req = 0;
     req.u.delg_req.filename = fname;
     req.u.delg_req.filename_len = strlen(fname);
     req.u.delg_req.num_tokens = 0;

     if(0 == strcmp(prop, "propagate"))
	  propagate = 1;
     else
	  propagate = 0;
     
     if(0 == strcmp(rights, "get"))
	  req.u.delg_req.rights = (propagate == 0) ? DELG_GET : DELG_GET | DELG_DELG;
     else if(0 == strcmp(rights, "put"))
	  req.u.delg_req.rights = (propagate == 0) ? DELG_PUT : DELG_PUT | DELG_DELG;
     if(0 == strcmp(rights, "both"))
	  req.u.delg_req.rights = (propagate == 0) ? DELG_GET | DELG_PUT : DELG_GET | DELG_PUT | DELG_DELG;;

     req.u.delg_req.host_len = strlen(host);
     req.u.delg_req.host = host;
     req.u.delg_req.time = atoi(time);


     if(STATUS_FAILURE == send_message(ssl, &req))
     {
	  perror("send req failed\n");
	  return 0;
     }

     return handle_client_message(ssl, &req, &res);
}

int do_client_loop(SSL *ssl)
{
     char buf[512];
     char *op, *fname, *uid, *rights, *host, *time, *propogate;
     printf("do loop\n");

     fprintf(stdout, "possible commands:\n");
     fprintf(stdout, "\tget <file_name>\n");
     fprintf(stdout, "\tput <file_name>\n");
     fprintf(stdout, "\tdelegate <file_name> <get/put/both> <host> <time> <propogate/not_propogate>\n");
     fprintf(stdout, "\tend-session\n");
     fflush(NULL);

     while(fgets(buf, sizeof(buf), stdin))
     {
	  op = strtok(buf, " ");
	  uid = "";
	  
	  if(0 == strcmp(buf, "get"))
	  {
	       fname = strtok(NULL, "\n");
	       get(ssl, fname, uid);
	  }
	  else if (0 == strcmp(buf, "put"))
	  {
	       fname = strtok(NULL, "\n");
	       put(ssl, fname, uid);
	  }
	  else if (0 == strcmp(buf, "delegate"))
	  {
	       fname = strtok(NULL, " ");	       
	       rights = strtok(NULL, " ");
	       host = strtok(NULL, " ");
	       time = strtok(NULL, " ");
	       propogate = strtok(NULL, " ");
	       delegate(ssl, fname, uid, rights, host, time, propogate);
	  }
	  else if (0 == strcmp(buf, "end-session"))
	       return 1;
	  else
	       fprintf(stderr, "Incorrect input\n");

	  memset(buf, 0, 256);
     }
		
     return 0;
}

int open_connection( SSL **ssl,   SSL_CTX **ctx, char *server_addr, char *server_port)
{
     BIO     *conn;
     long    err;
     char addr_buf[100] = "";

     sprintf(addr_buf, "%s:%s", server_addr, server_port);
     printf("[%s]\n",addr_buf);

     *ctx = setup_client_ctx(  );
 	
     conn = BIO_new_connect(addr_buf);
     if (!conn)
	  handle_error("Error creating connection BIO");
 
     if (BIO_do_connect(conn) <= 0)
	  handle_error("Error connecting to remote machine");
 
     *ssl = SSL_new(*ctx);
     SSL_set_bio(*ssl, conn, conn);
     if (SSL_connect(*ssl) <= 0)
	  handle_error("Error connecting SSL object");
     if ((err = post_connection_check(*ssl, SERVER)) != X509_V_OK)
     {
	  fprintf(stderr, "-Error: peer certificate: %s\n",
		  X509_verify_cert_error_string(err));
	  handle_error("Error checking SSL object after connection");
     }
     fprintf(stderr, "SSL Connection opened\n");

     return 0;
}

int close_connection( SSL *ssl,   SSL_CTX *ctx)
{
     SSL_free(ssl);
     SSL_CTX_free(ctx);

     return 0;
}

int start_session(char *server_addr, char *server_port)
{
     SSL *ssl;
     SSL_CTX *ctx;

     open_connection(&ssl, &ctx, server_addr, server_port);
     
     if (do_client_loop(ssl))
	  SSL_shutdown(ssl);
     else
	  SSL_clear(ssl);
     
     fprintf(stdout, "SSL Connection closed\n");
     close_connection(ssl, ctx);
     return 0; 	
}
 
int main(int argc, char *argv[])
{
     init_OpenSSL(  );
     seed_prng(  );

     if(argc < 4) 
     {
	  fprintf(stderr, "usage: ./client start-session host port\n");
	  exit(1);
     }
     if(0 == strcmp(argv[1], "start-session"))
	  start_session(argv[2], argv[3]);

     return 0;
}

