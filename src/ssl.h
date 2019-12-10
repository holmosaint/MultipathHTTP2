#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

#include <nghttp2/nghttp2.h>

#ifndef _SSL
#define _SSL

#ifndef OPENSSL_NO_NEXTPROTONEG
/* NPN TLS extension client callback. We check that server advertised
   the HTTP/2 protocol the nghttp2 library supports. If not, exit
   the program. */
int select_next_proto_cb(SSL *ssl, unsigned char **out, unsigned char *outlen,
                         const unsigned char *in, unsigned int inlen,
                         void *arg);
#endif /* !OPENSSL_NO_NEXTPROTONEG */

/* Create SSL_CTX. */
SSL_CTX *create_ssl_ctx(void);

/* Create SSL object */
SSL *create_ssl(SSL_CTX *ssl_ctx);

#endif