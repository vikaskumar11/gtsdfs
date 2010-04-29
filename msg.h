#ifndef __MSG_H__
#define __MSG_H__

#include <stdint.h>
#include <stdio.h>
#include <malloc.h>
#include <string.h>
#include <assert.h>
#include <arpa/inet.h>

#define STATUS_SUCCESS 0
#define STATUS_FAILURE 1

#define PUSH(c, ptr, len) ({           \
    memcpy((c->buf+c->off), ptr, (len)); \
    c->off += (len);                     \
})

#define POP(c, ptr, len) ({   \
    memcpy(ptr, (c->buf+c->off), (len)); \
    c->off += (len); \
})

#define pop1(c) ({                              \
  uint32_t _w1;                                 \
  _w1 = (*(uint8_t*)(c->buf+c->off));           \
   c->off+=1;                                   \
  _w1;                                          \
})

#define pop2(c) ({                              \
  uint16_t _w2=0;                               \
  uint8_t _c;                                   \
  _c = pop1(c);                                 \
  _w2 |= ((_c & 0xff) << 8);                    \
  _c = pop1(c);                                 \
  _w2 |= ((_c & 0xff));                         \
  _w2;                                          \
})

/*#define pop4(c) ({                               \
  uint32_t _w4=0;                               \
  uint8_t _c;                                   \
  _c = pop1(c);                                  \
  _w4 |= ((_c & 0xff) << 24);                   \
  _c = pop1(c);                                  \
  _w4 |= ((_c & 0xff) << 16);                   \
  _c = pop1(c);                                  \
  _w4 |= ((_c & 0xff) << 8);                    \
  _c = pop1(c);                                  \
  _w4 |= ((_c & 0xff));                         \
  _w4;                                          \
})*/

#define pop4(c) ({                              \
  uint32_t _w4=0;                               \
  _w4 = *(unsigned int *)(c->buf+c->off);       \
  c->off += 4; 					\
  _w4;                                          \
})

#define REQ_GET   1
#define RSP_GET   2
#define REQ_PUT   3
#define RSP_PUT   4
#define REQ_AUTH  5
#define RSP_AUTH  6
#define REQ_DELG  7
#define RSP_DELG  8

#define MSG_HDR_SIZE 5
#define GET_REQ_SIZE 5
#define GET_RSP_SIZE 5
#define PUT_REQ_SIZE 9
#define PUT_RSP_SIZE 1
#define AUTH_REQ_SIZE 4
#define AUTH_RSP_SIZE 1
#define TOKEN_SIZE   9

#define DELG_GET 1
#define DELG_PUT 2

#define MAX_TOKENS  5

typedef int status_t;


struct fuid {
  uint32_t len;
  char *id;
};

typedef struct fuid fuid_t;

struct msg_hdr {
  uint8_t type;
  uint32_t tot_len;
};

typedef struct msg_hdr msg_hdr_t;

struct auth_req {
  fuid_t uid;
};

typedef struct auth_req auth_req_t;

struct auth_resp {
  uint8_t status;
};

typedef struct auth_resp auth_resp_t;

struct token_info {
  fuid_t uid;  
  uint8_t is_last_token;
  uint32_t len;  
  char *tok;
};

typedef struct token_info token_info_t;

struct get_req {
  uint8_t del_req;
  uint32_t filename_len;
  char *filename;  
  uint32_t num_tokens;
  token_info_t tok_info[MAX_TOKENS];
};

typedef struct get_req get_req_t;

struct get_resp {
  uint8_t status;
  uint32_t filelen;
  char *data;
};

typedef struct get_resp get_resp_t;

struct put_req {
  uint8_t del_req;
  uint32_t filename_len;
  char *filename;
  uint32_t num_tokens;
  token_info_t tok_info[MAX_TOKENS];
  uint32_t file_len;
  char *data;
};

typedef struct put_req put_req_t;

struct put_resp {
  uint8_t status;
};

typedef struct put_resp put_resp_t;

struct delg_req {
  uint8_t del_req;
  uint32_t filename_len;
  char *filename;
  uint32_t num_tokens;
  token_info_t tok_info[MAX_TOKENS];
  uint32_t rights;
  uint32_t host_len;
  uint32_t time;
  char *host;
  uint32_t propagate   ;
};

typedef struct delg_req delg_req_t;

struct delg_resp {
  uint8_t status;
};

typedef struct delg_resp delg_resp_t;

struct payload {
  char *buf;
  unsigned int off;
  unsigned int wire_off;
};

typedef struct payload payload_t;


struct msg {
  msg_hdr_t hdr;

  union {
    auth_req_t auth_req;
    auth_resp_t auth_resp;
    get_req_t  get_req;
    get_resp_t get_resp;
    put_req_t put_req;
    put_resp_t put_resp;
    delg_req_t delg_req;
    delg_resp_t delg_resp;   
  } u;

  payload_t *pkt;
};

typedef struct msg msg_t;


/*void message_dump(payload_t *pkt, int pkt_len);
status_t send_payload(SSL *ssl, payload_t *pkt, unsigned int pkt_len);
status_t receive_payload(SSL *ssl, msg_t *msg);
status_t send_get_request(SSL *ssl, msg_t *msg);
status_t send_get_resp(SSL *ssl, msg_t *msg);
status_t parse_get_req(payload_t *pkt, msg_t *msg);
status_t parse_get_resp(payload_t *pkt, msg_t *msg);
status_t send_put_request(SSL *ssl, msg_t *msg);
status_t send_put_resp(SSL *ssl, msg_t *msg);
status_t parse_put_req(payload_t *pkt, msg_t *msg);
status_t parse_put_resp(payload_t *pkt, msg_t *msg);
status_t send_auth_request(SSL *ssl, msg_t *msg);
status_t send_auth_resp(SSL *ssl, msg_t *msg);
status_t parse_auth_req(payload_t *pkt, msg_t *msg);
status_t parse_auth_resp(payload_t *pkt, msg_t *msg);
status_t send_message(SSL *ssl, msg_t *msg);
status_t recv_message(SSL *ssl, msg_t *msg);*/


#endif
