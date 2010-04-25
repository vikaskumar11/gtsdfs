#include "common.h"

void _handle_error(const char *file, int lineno, const char *msg)
{
    fprintf(stderr, "** %s:%i %s\n", file, lineno, msg);
    ERR_print_errors_fp(stderr);
    exit(-1);
}

void init_OpenSSL(void)
{
    if (!THREAD_setup() || !SSL_library_init())
    {
        fprintf(stderr, "** OpenSSL initialization failed!\n");
        exit(-1);
    }
    SSL_load_error_strings();
}

int verify_callback(int ok, X509_STORE_CTX *store)
{
    char data[256];
 
    if (!ok)
    {
        X509 *cert = X509_STORE_CTX_get_current_cert(store);
        int  depth = X509_STORE_CTX_get_error_depth(store);
        int  err = X509_STORE_CTX_get_error(store);
 
        fprintf(stderr, "-Error with certificate at depth: %i\n", depth);
        X509_NAME_oneline(X509_get_issuer_name(cert), data, 256);
        fprintf(stderr, "  issuer   = %s\n", data);
        X509_NAME_oneline(X509_get_subject_name(cert), data, 256);
        fprintf(stderr, "  subject  = %s\n", data);
        fprintf(stderr, "  err %i:%s\n", err, X509_verify_cert_error_string(err));
    }
 
    return ok;
}

long post_connection_check(SSL *ssl, char *host)
{
    X509      *cert;
    X509_NAME *subj;
    char      data[256];
    int       extcount;
    int       ok = 0;
 
    /* Checking the return from SSL_get_peer_certificate here is not strictly
     * necessary.  With our example programs, it is not possible for it to return
     * NULL.  However, it is good form to check the return since it can return NULL
     * if the examples are modified to enable anonymous ciphers or for the server
     * to not require a client certificate.
     */
    if (!(cert = SSL_get_peer_certificate(ssl)) || !host)
        goto err_occured;
    if ((extcount = X509_get_ext_count(cert)) > 0)
    {
        int i;
 
        for (i = 0;  i < extcount;  i++)
        {
            char              *extstr;
            X509_EXTENSION    *ext;
 
            ext = X509_get_ext(cert, i);
            extstr = (char*) OBJ_nid2sn(OBJ_obj2nid(X509_EXTENSION_get_object(ext)));
 
            if (!strcmp(extstr, "subjectAltName"))
            {
                int                  j;
                unsigned char        *data;
                STACK_OF(CONF_VALUE) *val;
                CONF_VALUE           *nval;
                X509V3_EXT_METHOD    *meth;
                void                 *ext_str = NULL;
 
                if (!(meth = X509V3_EXT_get(ext)))
                    break;
                data = ext->value->data;

#if (OPENSSL_VERSION_NUMBER > 0x00907000L)
                if (meth->it)
                  ext_str = ASN1_item_d2i(NULL, &data, ext->value->length,
                                          ASN1_ITEM_ptr(meth->it));
                else
                  ext_str = meth->d2i(NULL, &data, ext->value->length);
#else
                ext_str = meth->d2i(NULL, &data, ext->value->length);
#endif
                val = meth->i2v(meth, ext_str, NULL);
                for (j = 0;  j < sk_CONF_VALUE_num(val);  j++)
                {
                    nval = sk_CONF_VALUE_value(val, j);
                    if (!strcmp(nval->name, "DNS") && !strcmp(nval->value, host))
                    {
                        ok = 1;
                        break;
                    }
                }
            }
            if (ok)
                break;
        }
    }
 
    if (!ok && (subj = X509_get_subject_name(cert)) &&
        X509_NAME_get_text_by_NID(subj, NID_commonName, data, 256) > 0)
    {
        data[255] = 0;
        if (strcasecmp(data, host) != 0)
            goto err_occured;
    }
 
    X509_free(cert);
    return SSL_get_verify_result(ssl);
 
err_occured:
    if (cert)
        X509_free(cert);
    return X509_V_ERR_APPLICATION_VERIFICATION;
}

void seed_prng(void)
{
  RAND_load_file("/dev/urandom", 1024);
}


/* This array will store all of the mutexes available to OpenSSL. */
static MUTEX_TYPE *mutex_buf = NULL;

static void locking_function(int mode, int n, const char * file, int line)
{
     if (mode & CRYPTO_LOCK)
	  MUTEX_LOCK(mutex_buf[n]);
     else
	  MUTEX_UNLOCK(mutex_buf[n]);
}

static unsigned long id_function(void)
{
     return ((unsigned long)THREAD_ID);
}

struct CRYPTO_dynlock_value
{
     MUTEX_TYPE mutex;
};

static struct CRYPTO_dynlock_value * dyn_create_function(const char *file,
							 int line)
{
     struct CRYPTO_dynlock_value *value;
     value = (struct CRYPTO_dynlock_value *)malloc(sizeof(
							struct CRYPTO_dynlock_value));
     if (!value)
	  return NULL;
     MUTEX_SETUP(value->mutex);
     return value;
}

static void dyn_lock_function(int mode, struct CRYPTO_dynlock_value *l,
			      const char *file, int line)
{
     if (mode & CRYPTO_LOCK)
	  MUTEX_LOCK(l->mutex);
     else
	  MUTEX_UNLOCK(l->mutex);
}

static void dyn_destroy_function(struct CRYPTO_dynlock_value *l,
				 const char *file, int line)
{
     MUTEX_CLEANUP(l->mutex);
     free(l);
}

int THREAD_setup(void)
{
     int i;
     mutex_buf = (MUTEX_TYPE *)malloc(CRYPTO_num_locks( ) * sizeof(MUTEX_TYPE));
     if (!mutex_buf)
	  return 0;
     for (i = 0; i < CRYPTO_num_locks( ); i++)
	  MUTEX_SETUP(mutex_buf[i]);
     CRYPTO_set_id_callback(id_function);
     CRYPTO_set_locking_callback(locking_function);     
     CRYPTO_set_dynlock_create_callback(dyn_create_function);
     CRYPTO_set_dynlock_lock_callback(dyn_lock_function);
     CRYPTO_set_dynlock_destroy_callback(dyn_destroy_function);
     return 1;
}

int THREAD_cleanup(void)
{
     int i;
     if (!mutex_buf)
	  return 0;
     CRYPTO_set_id_callback(NULL);
     CRYPTO_set_locking_callback(NULL);
     CRYPTO_set_dynlock_create_callback(NULL);
     CRYPTO_set_dynlock_lock_callback(NULL);
     CRYPTO_set_dynlock_destroy_callback(NULL);
     for (i = 0; i < CRYPTO_num_locks( ); i++)
	  MUTEX_CLEANUP(mutex_buf[i]);
     free(mutex_buf);
     mutex_buf = NULL;
     return 1;
}
