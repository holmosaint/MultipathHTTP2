#include <nghttp2/nghttp2.h>

#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

#include <pthread.h>

#include "url_parser.h"

#ifndef HTTP2
#define HTTP2

#define ARRLEN(x) (sizeof(x) / sizeof(x[0]))

typedef struct {
  /* The NULL-terminated URI string to retrieve. */
  const char *uri;
  /* Parsed result of the |uri| */
  struct http_parser_url *u;
  /* The authority portion of the |uri|, not NULL-terminated */
  char *authority;
  /* The path portion of the |uri|, including query, not
     NULL-terminated */
  char *path;
  /* The length of the |authority| */
  size_t authoritylen;
  /* The length of the |path| */
  size_t pathlen;
  /* The stream ID of this stream */
  int32_t stream_id;

  /* Range */
  pthread_mutex_t stream_mutex;
  ssize_t st;
  ssize_t en;
  ssize_t received_bytes;
  FILE *stream_file;
  struct timeval st_time;
  struct timeval en_time;
} http2_stream_data;

typedef struct {
  int CDN_id;
  nghttp2_session *session;
  struct evdns_base *dnsbase;
  struct bufferevent *bev;
  struct {
    http2_stream_data *request_stream_data;
    http2_stream_data *ping_stream_data;
  } stream;
} http2_session_data;

typedef struct {
  pthread_t tid;

  ssize_t end_point;

  struct http_parser_url u;
  char url[500];

  double RTT;
  struct timeval ping_start;
  int RTT_updated;

  double BW;

  http2_session_data *session_data;
  SSL_CTX *ssl_ctx;
  struct event_base *evbase;
  const char *host;
  uint16_t port;

  // For output
  pthread_mutex_t CDN_range_mutex;
  FILE *range_file;  // Record the ranges that the CDN responsible for,
                     // format: "xx-xxx"
} CDN_node;

#define CDN_NUM 3
CDN_node CDN[CDN_NUM];
ssize_t content_size;
uint8_t global_data_buf[(int)1e8];

/* Look up CDN id by session address*/
int CDN_lookup(http2_session_data *session);

http2_stream_data *create_http2_stream_data(const char *uri,
                                            struct http_parser_url *u);

void delete_http2_stream_data(http2_stream_data *stream_data);

/* Initializes |session_data| */
http2_session_data *create_http2_session_data(struct event_base *evbase);

void delete_http2_session_data(http2_session_data *session_data);

void initialize_nghttp2_session(http2_session_data *session_data);

/* Serialize the frame and send (or buffer) the data to
   bufferevent. */
int session_send(http2_session_data *session_data);

int send_PING_frame(int CDN_id);

#endif