#include <nghttp2/nghttp2.h>

#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

#include <pthread.h>

#include "url_parser.h"

#ifndef HTTP2
#define HTTP2

#define ARRLEN(x) (sizeof(x) / sizeof(x[0]))

#define GLOBAL_SCHE_SUCC 0
#define GLOBAL_SCHE_NO_EMPTY_STREAM 1
#define GLOBAL_SCHE_EARLY 2
#define GLOBAL_CHUNK_THRE 3
#define GLOBAL_LACK_CDN 4

#define STREAM_END 1

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

  /* Stream End Flag */
  uint8_t end_flag;

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
  pthread_mutex_t session_mutex;
  struct {
    http2_stream_data *request_stream_data;
    http2_stream_data *extra_request_stream_data;
  } stream;
} http2_session_data;

typedef struct {
  pthread_mutex_t CDN_mutex;

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
  FILE *range_file;  // Record the ranges that the CDN responsible for,
                     // format: "xx-xxx"
} CDN_node;

#define CDN_NUM 3
pthread_mutex_t global_mutex;
CDN_node CDN[CDN_NUM];
ssize_t content_size, estimated_total_content_left, total_content_left;
uint8_t global_data_buf[(int)1e8];
int CDN_alive;

#define CHUNK_SIZE 1000

#define MAKE_NV(NAME, VALUE, VALUELEN)                             \
  {                                                                \
    (uint8_t *)NAME, (uint8_t *)VALUE, sizeof(NAME) - 1, VALUELEN, \
        NGHTTP2_NV_FLAG_NONE                                       \
  }

#define MAKE_NV2(NAME, VALUE)                                               \
  {                                                                         \
    (uint8_t *)NAME, (uint8_t *)VALUE, sizeof(NAME) - 1, sizeof(VALUE) - 1, \
        NGHTTP2_NV_FLAG_NONE                                                \
  }

nghttp2_nv *construct_header(http2_stream_data *stream_data, ssize_t st,
                             ssize_t en);

void submit_init_request(http2_session_data *session_data);

void change_stream_end(int CDN_id, ssize_t new_en);

/* Calculate content size for each CDN */
void cal_content_size(ssize_t *D);

/* Schdule Stream*/
int schedule_stream(int CDN_id, http2_stream_data **stream_data);

/* Global Scheduler */
int global_schedule(int CDN_id);

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