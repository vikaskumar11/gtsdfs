#include <stdint.h>
#include <stdio.h>
#include <malloc.h>
#include <string.h>
#include <assert.h>
#include <arpa/inet.h>

#include "msg.h"

status_t send_get_request(msg_t *msg) {
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


  free(payload.buf);
  return STATUS_SUCCESS;
};

status_t send_get_resp(msg_t *msg) {
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


status_t send_put_request(msg_t *msg) {
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


  free(payload.buf);
  return STATUS_SUCCESS;
};

status_t send_put_resp(msg_t *msg) {
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

status_t send_auth_request(msg_t *msg) {
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


  free(payload.buf);
  return STATUS_SUCCESS;
};

status_t send_auth_resp(msg_t *msg) {
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
