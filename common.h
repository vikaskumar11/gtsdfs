#ifndef COMMON_H
#define COMMON_H

#include <string.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>


#define THREAD_TYPE                    pthread_t
#define THREAD_CREATE(tid, entry, arg) pthread_create(&(tid), NULL, \
                                                      (entry), (arg))
#define MUTEX_TYPE pthread_mutex_t
#define MUTEX_SETUP(x) pthread_mutex_init(&(x), NULL)
#define MUTEX_CLEANUP(x) pthread_mutex_destroy(&(x))
#define MUTEX_LOCK(x) pthread_mutex_lock(&(x))
#define MUTEX_UNLOCK(x) pthread_mutex_unlock(&(x))
#define THREAD_ID pthread_self( )

#define PORT            "16001"
#define SERVER          "localhost"
#define CLIENT          "localhost"

#define handle_error(msg)  _handle_error(__FILE__, __LINE__, msg)
void _handle_error(const char *file, int lineno, const char *msg);

void init_OpenSSL(void);

int verify_callback(int ok, X509_STORE_CTX *store);

long post_connection_check(SSL *ssl, char *host);

void seed_prng(void);

int THREAD_setup(void);

int THREAD_cleanup(void);

#endif /* COMMON_H */
