#include "msg.h"
//#include "msg.c"

void message_dump(payload_t *pkt, int pkt_len) {
     int lim, count;

     lim = pkt_len / 4;
 
     if(lim == 0) lim = 1;

     printf("\nSending Message >> \n");
     for (count = 0; count < lim; count++)
     {
	  printf("  0x%04x: 0x%08x\n",
		 count * 4, *(unsigned int *)&pkt->buf[count * 4]);
     }
}

status_t send_payload(SSL *ssl, payload_t *pkt, unsigned int pkt_len) {

     int ret = 0;
     int bytes_written = 0;

     pkt->wire_off = 0;
     while(bytes_written < pkt_len) {

	  ret = SSL_write(ssl, pkt->buf+pkt->wire_off, (pkt_len-bytes_written));

	  switch(SSL_get_error(ssl, ret)) {
	  case SSL_ERROR_NONE:
	       bytes_written += ret;
	       pkt->wire_off += ret;
	       continue;
	       break;
	  case SSL_ERROR_ZERO_RETURN:
	       perror("SSL_Write Error: Possibly connection closed\n");
	       goto fail;
	       break;
	  case SSL_ERROR_WANT_READ:
	  case SSL_ERROR_WANT_WRITE:
	       perror("SSL_Write Error: Want Read/Want Write\n");
	       goto fail;
	       break;
	  case SSL_ERROR_WANT_CONNECT:
	  case SSL_ERROR_WANT_ACCEPT:
	       perror("SSL Write Error: Want Connect/Want Accept\n");
	       goto fail;
	       break;
	  default:
	       perror("SSL_Write Unkown error\n");
	       goto fail;
	       break;
	  }
     }

     message_dump(pkt, pkt_len);
     return STATUS_SUCCESS;

fail:
     return STATUS_FAILURE;
}

status_t receive_payload(SSL *ssl, msg_t *msg) {
     payload_t *pkt;
     int ret = 0;
     int bytes_read = 0;
     char buf[MSG_HDR_SIZE];
     uint32_t tmp32;

     pkt = malloc(sizeof(payload_t));
     memset(pkt, 0, sizeof(payload_t));

     ret = SSL_read(ssl, buf, MSG_HDR_SIZE);

     if(ret != MSG_HDR_SIZE) {
	  perror("Unable to receive message header\n");
	  return STATUS_FAILURE;
     }
  
     pkt->buf = buf;
     msg->hdr.type = pop1(pkt);
     tmp32 = pop4(pkt);
     msg->hdr.tot_len = ntohl(tmp32);

     pkt->buf = malloc(msg->hdr.tot_len);
     if(pkt->buf == NULL) {
	  free(pkt);
	  return STATUS_FAILURE;
     }

     bytes_read = MSG_HDR_SIZE;
     pkt->wire_off = MSG_HDR_SIZE;
     while(bytes_read < msg->hdr.tot_len) {

	  ret = SSL_read(ssl, pkt->buf+pkt->wire_off, (msg->hdr.tot_len-bytes_read));
    
	  switch(SSL_get_error(ssl, ret)) {
	  case SSL_ERROR_NONE:
	       bytes_read += ret;
	       pkt->wire_off += ret;
	       continue;
	       break;
	  case SSL_ERROR_ZERO_RETURN:
	       perror("SSL_read Error: Possibly connection closed\n");
	       goto fail;
	       break;
	  case SSL_ERROR_WANT_READ:
	  case SSL_ERROR_WANT_WRITE:
	       perror("SSL_read Error: Want Read/Want Write\n");
	       goto fail;
	       break;
	  case SSL_ERROR_WANT_CONNECT:
	  case SSL_ERROR_WANT_ACCEPT:
	       perror("SSL read Error: Want Connect/Want Accept\n");
	       goto fail;
	       break;
	  default:
	       perror("SSL_read Unkown error\n");
	       goto fail;
	       break;
	  }
     }

     msg->pkt = pkt;

     printf("Received message >>\n");
     message_dump(pkt, msg->hdr.tot_len);

     return STATUS_SUCCESS;

fail:
     free(pkt->buf);
     free(pkt);
     return STATUS_FAILURE;
}



status_t send_get_request(SSL *ssl, msg_t *msg) {
     payload_t payload;
     payload_t *pkt = &payload;
     uint32_t tmp32;
 
     msg->hdr.type = REQ_GET;
     msg->hdr.tot_len = MSG_HDR_SIZE + GET_REQ_SIZE;
     msg->hdr.tot_len += msg->u.get_req.filename_len;

     if(msg->u.get_req.del_req) {
	  int cnt = 0;
	  for( ; cnt < msg->u.get_req.num_tokens; cnt++) {
	       msg->hdr.tot_len += TOKEN_SIZE + msg->u.get_req.tok_info[cnt].len + msg->u.get_req.tok_info[cnt].uid.len;
	  }
     }

     memset(pkt, 0, sizeof(payload_t));

     payload.buf = malloc(msg->hdr.tot_len);

     if(payload.buf == NULL)
	  return STATUS_FAILURE;

     PUSH(pkt, &msg->hdr.type, 1);
 
     tmp32 = htonl(msg->hdr.tot_len);
     PUSH(pkt, &tmp32, 4);

     PUSH(pkt, &msg->u.get_req.del_req, 1);
     tmp32 = htonl(msg->u.get_req.filename_len);
     PUSH(pkt, &tmp32, 4);

     PUSH(pkt, msg->u.get_req.filename, msg->u.get_req.filename_len);
  
     if(msg->u.get_req.del_req) {
	  int cnt;

	  for(cnt = 0; cnt < msg->u.get_req.num_tokens; cnt++) {
	       tmp32 = htonl(msg->u.get_req.tok_info[cnt].uid.len);
	       PUSH(pkt, &tmp32, 4);

	       PUSH(pkt, msg->u.get_req.tok_info[cnt].uid.id, msg->u.get_req.tok_info[cnt].uid.len);

	       PUSH(pkt, &msg->u.get_req.tok_info[cnt].is_last_token, 1);
	       tmp32 = htonl(msg->u.get_req.tok_info[cnt].len);
	       PUSH(pkt, &tmp32, 4);
	       PUSH(pkt, msg->u.get_req.tok_info[cnt].tok, msg->u.get_req.tok_info[cnt].len);

	  }
     }

     assert(payload.off == msg->hdr.tot_len);
 
     /* send the message */
     send_payload(ssl, pkt, msg->hdr.tot_len);

     free(payload.buf);
     return STATUS_SUCCESS;
};

status_t send_get_resp(SSL *ssl, msg_t *msg) {
     payload_t payload;
     payload_t *pkt = &payload;
     uint32_t tmp32;
 
     msg->hdr.type = RSP_GET;
     msg->hdr.tot_len = MSG_HDR_SIZE + GET_RSP_SIZE;
     msg->hdr.tot_len += msg->u.get_resp.filelen;

     payload.buf = malloc(msg->hdr.tot_len);

     if(payload.buf == NULL)
	  return STATUS_FAILURE;

     /* Header */
     PUSH(pkt, &msg->hdr.type, 1);
     tmp32 = htonl(msg->hdr.tot_len);
     PUSH(pkt, &tmp32, 4);

     /* Get Response */
     PUSH(pkt, &msg->u.get_resp.status, 1);
     tmp32 = htonl(msg->u.get_resp.filelen);
     PUSH(pkt, &tmp32, 4);

     if(msg->u.get_resp.filelen) {
	  PUSH(pkt, msg->u.get_resp.data, msg->u.get_resp.filelen);
     }

     assert(payload.off == msg->hdr.tot_len);

     /* send the payload */
     send_payload(ssl, pkt, msg->hdr.tot_len);

     free(payload.buf);

     return STATUS_SUCCESS;

}

status_t parse_get_req(payload_t *pkt, msg_t *msg) {

     pkt->off = MSG_HDR_SIZE; 

     msg->u.get_req.del_req = pop1(pkt);
     msg->u.get_req.filename_len = ntohl(pop4(pkt));

     msg->u.get_req.filename = malloc(msg->u.get_req.filename_len);
     if(msg->u.get_req.filename == NULL)
	  return STATUS_FAILURE;

     POP(pkt, msg->u.get_req.filename, msg->u.get_req.filename_len);

     if(msg->u.get_req.del_req) {
	  int cnt = 0, last_tok = 0;

	  while(!last_tok) {
	       msg->u.get_req.tok_info[cnt].uid.len = ntohl(pop4(pkt));
	       msg->u.get_req.tok_info[cnt].uid.id = malloc(msg->u.get_req.tok_info[cnt].uid.len);

	       if(msg->u.get_req.tok_info[cnt].uid.id == NULL)
		    return STATUS_FAILURE;

	       POP(pkt, msg->u.get_req.tok_info[cnt].uid.id, msg->u.get_req.tok_info[cnt].uid.len);
	       msg->u.get_req.tok_info[cnt].is_last_token = pop1(pkt);
	       last_tok = msg->u.get_req.tok_info[cnt].is_last_token;
	       msg->u.get_req.tok_info[cnt].len = ntohl(pop4(pkt));

	       msg->u.get_req.tok_info[cnt].tok = malloc(msg->u.get_req.tok_info[cnt].len);

	       if(msg->u.get_req.tok_info[cnt].tok == NULL)
		    return STATUS_FAILURE;

	       POP(pkt, msg->u.get_req.tok_info[cnt].tok, msg->u.get_req.tok_info[cnt].len);

	       cnt++;
	  }

	  msg->u.get_req.num_tokens = cnt;
     }

     return STATUS_SUCCESS;
}

status_t parse_get_resp(payload_t *pkt, msg_t *msg) {
     uint32_t tmp32;

     pkt->off = MSG_HDR_SIZE; 
  
     msg->u.get_resp.status = pop1(pkt);

     if(msg->u.get_resp.status == STATUS_SUCCESS) {
	  tmp32 = pop4(pkt);
	  msg->u.get_resp.filelen = ntohl(tmp32);

	  msg->u.get_resp.data = malloc(msg->u.get_resp.filelen);
	  if(msg->u.get_resp.data == NULL)
	       return STATUS_FAILURE;

	  POP(pkt, msg->u.get_resp.data, msg->u.get_resp.filelen);
     }

     return STATUS_SUCCESS;
}


status_t send_put_request(SSL *ssl, msg_t *msg) {
     payload_t payload;
     payload_t *pkt = &payload;
     uint32_t tmp32;
 
     msg->hdr.type = REQ_PUT;
     msg->hdr.tot_len = MSG_HDR_SIZE + PUT_REQ_SIZE;
     msg->hdr.tot_len += msg->u.put_req.filename_len;
     msg->hdr.tot_len += msg->u.put_req.file_len;

     if(msg->u.put_req.del_req) {
	  int cnt = 0;
	  for( ; cnt < msg->u.put_req.num_tokens; cnt++) {
	       msg->hdr.tot_len += TOKEN_SIZE + msg->u.put_req.tok_info[cnt].len + msg->u.put_req.tok_info[cnt].uid.len;
	  }
     }

     payload.buf = malloc(msg->hdr.tot_len);

     if(payload.buf == NULL)
	  return STATUS_FAILURE;


     PUSH(pkt, &msg->hdr.type, 1);
 
     tmp32 = htonl(msg->hdr.tot_len);
     PUSH(pkt, &tmp32, 4);

     PUSH(pkt, &msg->u.put_req.del_req, 1);
     tmp32 = htonl(msg->u.put_req.filename_len);
     PUSH(pkt, &tmp32, 4);

     PUSH(pkt, msg->u.put_req.filename, msg->u.put_req.filename_len);
  
     if(msg->u.put_req.del_req) {
	  int cnt;

	  for(cnt = 0; cnt < msg->u.put_req.num_tokens; cnt++) {
	       tmp32 = htonl(msg->u.put_req.tok_info[cnt].uid.len);
	       PUSH(pkt, &tmp32, 4);

	       PUSH(pkt, msg->u.put_req.tok_info[cnt].uid.id, msg->u.put_req.tok_info[cnt].uid.len);

	       PUSH(pkt, &msg->u.put_req.tok_info[cnt].is_last_token, 1);
	       tmp32 = htonl(msg->u.put_req.tok_info[cnt].len);
	       PUSH(pkt, &tmp32, 4);
	       PUSH(pkt, msg->u.put_req.tok_info[cnt].tok, msg->u.put_req.tok_info[cnt].len);

	  }
     }

     tmp32 = htonl(msg->u.put_req.file_len);
     PUSH(pkt, &tmp32, 4);
     PUSH(pkt, msg->u.put_req.data, msg->u.put_req.file_len);

     assert(payload.off == msg->hdr.tot_len);
 
     /* send the message */
     send_payload(ssl, pkt, msg->hdr.tot_len);

     free(payload.buf);
     return STATUS_SUCCESS;
};

status_t send_put_resp(SSL *ssl, msg_t *msg) {
     payload_t payload;
     payload_t *pkt = &payload;
     uint32_t tmp32;
 
     msg->hdr.type = RSP_PUT;
     msg->hdr.tot_len = MSG_HDR_SIZE + PUT_RSP_SIZE;

     payload.buf = malloc(msg->hdr.tot_len);

     if(payload.buf == NULL)
	  return STATUS_FAILURE;

     /* Header */
     PUSH(pkt, &msg->hdr.type, 1);
     tmp32 = htonl(msg->hdr.tot_len);
     PUSH(pkt, &tmp32, 4);

     /* Put Response */
     PUSH(pkt, &msg->u.put_resp.status, 1);
  
     assert(payload.off == msg->hdr.tot_len);

     /* send the payload */
     send_payload(ssl, pkt, msg->hdr.tot_len);

     free(payload.buf);

     return STATUS_SUCCESS;

}

status_t parse_put_req(payload_t *pkt, msg_t *msg) {
     pkt->off = MSG_HDR_SIZE; 

     msg->u.put_req.del_req = pop1(pkt);
     msg->u.put_req.filename_len = ntohl(pop4(pkt));

     msg->u.put_req.filename = malloc(msg->u.put_req.filename_len);
     if(msg->u.put_req.filename == NULL)
	  return STATUS_FAILURE;

     POP(pkt, msg->u.put_req.filename, msg->u.put_req.filename_len);

     if(msg->u.put_req.del_req) {
	  int cnt = 0, last_tok = 0;

	  while(!last_tok) {
	       msg->u.put_req.tok_info[cnt].uid.len = ntohl(pop4(pkt));
	       msg->u.put_req.tok_info[cnt].uid.id = malloc(msg->u.put_req.tok_info[cnt].uid.len);

	       if(msg->u.put_req.tok_info[cnt].uid.id == NULL)
		    return STATUS_FAILURE;

	       POP(pkt, msg->u.put_req.tok_info[cnt].uid.id, msg->u.put_req.tok_info[cnt].uid.len);
	       msg->u.put_req.tok_info[cnt].is_last_token = pop1(pkt);
	       last_tok = msg->u.put_req.tok_info[cnt].is_last_token;
	       msg->u.put_req.tok_info[cnt].len = ntohl(pop4(pkt));

	       msg->u.put_req.tok_info[cnt].tok = malloc(msg->u.put_req.tok_info[cnt].len);

	       if(msg->u.put_req.tok_info[cnt].tok == NULL)
		    return STATUS_FAILURE;

	       POP(pkt, msg->u.put_req.tok_info[cnt].tok, msg->u.put_req.tok_info[cnt].len);

	       cnt++;
	  }

	  msg->u.put_req.num_tokens = cnt;
     }

     msg->u.put_req.file_len = ntohl(pop4(pkt));
     msg->u.put_req.data = malloc(msg->u.put_req.file_len);

     if(msg->u.put_req.data == NULL)
	  return STATUS_FAILURE;

     POP(pkt, msg->u.put_req.data, msg->u.put_req.file_len);

     return STATUS_SUCCESS;
}

status_t parse_put_resp(payload_t *pkt, msg_t *msg) {

     pkt->off = MSG_HDR_SIZE; 
  
     msg->u.put_resp.status = pop1(pkt);

     return STATUS_SUCCESS;
}

status_t send_auth_request(SSL *ssl, msg_t *msg) {
     payload_t payload;
     payload_t *pkt = &payload;
     uint32_t tmp32;
 
     msg->hdr.type = REQ_AUTH;
     msg->hdr.tot_len = MSG_HDR_SIZE + AUTH_REQ_SIZE;
     msg->hdr.tot_len += msg->u.auth_req.uid.len;

     payload.buf = malloc(msg->hdr.tot_len);

     if(payload.buf == NULL)
	  return STATUS_FAILURE;

     PUSH(pkt, &msg->hdr.type, 1);
 
     tmp32 = htonl(msg->hdr.tot_len);
     PUSH(pkt, &tmp32, 4);

     tmp32 = htonl(msg->u.auth_req.uid.len);
     PUSH(pkt, &tmp32, 4);
     PUSH(pkt, msg->u.auth_req.uid.id, msg->u.auth_req.uid.len);

     assert(payload.off == msg->hdr.tot_len);
 
     /* send the message */
     send_payload(ssl, pkt, msg->hdr.tot_len);

     free(payload.buf);
     return STATUS_SUCCESS;
};

status_t send_auth_resp(SSL *ssl, msg_t *msg) {
     payload_t payload;
     payload_t *pkt = &payload;
     uint32_t tmp32;
 
     msg->hdr.type = RSP_GET;
     msg->hdr.tot_len = MSG_HDR_SIZE + AUTH_RSP_SIZE;

     payload.buf = malloc(msg->hdr.tot_len);

     if(payload.buf == NULL)
	  return STATUS_FAILURE;

     /* Header */
     PUSH(pkt, &msg->hdr.type, 1);
     tmp32 = htonl(msg->hdr.tot_len);
     PUSH(pkt, &tmp32, 4);

     /* Auth Response */
     PUSH(pkt, &msg->u.auth_resp.status, 1);

     assert(payload.off == msg->hdr.tot_len);

     /* send the payload */
     send_payload(ssl, pkt, msg->hdr.tot_len);

     free(payload.buf);

     return STATUS_SUCCESS;

}

status_t parse_auth_req(payload_t *pkt, msg_t *msg) {

     pkt->off = MSG_HDR_SIZE; 

     msg->u.auth_req.uid.len = ntohl(pop4(pkt));

     msg->u.auth_req.uid.id = malloc(msg->u.auth_req.uid.len);
     if(msg->u.auth_req.uid.id == NULL)
	  return STATUS_FAILURE;

     POP(pkt, msg->u.auth_req.uid.id, msg->u.auth_req.uid.len);
  
     return STATUS_SUCCESS;
}

status_t parse_auth_resp(payload_t *pkt, msg_t *msg) {
     pkt->off = MSG_HDR_SIZE; 
  
     msg->u.auth_resp.status = pop1(pkt);

     return STATUS_SUCCESS;
}

status_t send_message(SSL *ssl, msg_t *msg) {

     switch(msg->hdr.type) {
     case REQ_GET:
	  send_get_request(ssl, msg);
	  break;
     case REQ_PUT:
	  send_put_request(ssl, msg);
	  break;
     case REQ_AUTH:
	  send_auth_request(ssl, msg);
	  break;
     case RSP_GET:
	  send_get_resp(ssl, msg);
	  break;
     case RSP_PUT:
	  send_put_resp(ssl, msg);
	  break;
     case RSP_AUTH:
	  send_auth_resp(ssl, msg);
	  break;
     default:
	  perror("send_message: Unknown request type\n");
	  return STATUS_FAILURE;
     }

     return STATUS_SUCCESS;
}

status_t recv_message(SSL *ssl, msg_t *msg) {

     if(STATUS_FAILURE == receive_payload(ssl, msg)) {
	  return STATUS_FAILURE;
     }

     switch(msg->hdr.type) {
     case REQ_GET:
	  parse_get_req(msg->pkt, msg);
	  break;
     case REQ_PUT:
	  parse_put_req(msg->pkt, msg);
	  break;
     case REQ_AUTH:
	  parse_auth_req(msg->pkt, msg);
	  break;
     case RSP_GET:
	  parse_get_resp(msg->pkt, msg);
	  break;
     case RSP_PUT:
	  parse_put_resp(msg->pkt, msg);
	  break;
     case RSP_AUTH:
	  parse_auth_resp(msg->pkt, msg);
	  break;
     default:
	  perror("recv_message: Unknown request type\n");
	  return STATUS_FAILURE;
     }

     return STATUS_SUCCESS;
}
