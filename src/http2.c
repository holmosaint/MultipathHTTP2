#include "string.h"

#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

#include <event2/bufferevent_ssl.h>
#include <event2/dns.h>
#include <event2/event.h>

#include <nghttp2/nghttp2.h>

#include "callbacks.h"
#include "http2.h"
#include "url_parser.h"

/* Look up CDN id by session address*/
int CDN_lookup(http2_session_data *session_data) {
  return session_data->CDN_id;
}

http2_stream_data *create_http2_stream_data(const char *uri,
                                            struct http_parser_url *u) {
  /* MAX 5 digits (max 65535) + 1 ':' + 1 NULL (because of snprintf) */
  size_t extra = 7;
  http2_stream_data *stream_data = malloc(sizeof(http2_stream_data));

  stream_data->uri = uri;
  stream_data->u = u;
  stream_data->stream_id = -1;

  stream_data->authoritylen = u->field_data[UF_HOST].len;
  stream_data->authority = malloc(stream_data->authoritylen + extra);
  memcpy(stream_data->authority, &uri[u->field_data[UF_HOST].off],
         u->field_data[UF_HOST].len);
  if (u->field_set & (1 << UF_PORT)) {
    stream_data->authoritylen +=
        (size_t)snprintf(stream_data->authority + u->field_data[UF_HOST].len,
                         extra, ":%u", u->port);
  }

  /* If we don't have path in URI, we use "/" as path. */
  stream_data->pathlen = 1;
  if (u->field_set & (1 << UF_PATH)) {
    stream_data->pathlen = u->field_data[UF_PATH].len;
  }
  if (u->field_set & (1 << UF_QUERY)) {
    /* +1 for '?' character */
    stream_data->pathlen += (size_t)(u->field_data[UF_QUERY].len + 1);
  }

  stream_data->path = malloc(stream_data->pathlen);
  if (u->field_set & (1 << UF_PATH)) {
    memcpy(stream_data->path, &uri[u->field_data[UF_PATH].off],
           u->field_data[UF_PATH].len);
  } else {
    stream_data->path[0] = '/';
  }
  if (u->field_set & (1 << UF_QUERY)) {
    stream_data->path[stream_data->pathlen - u->field_data[UF_QUERY].len - 1] =
        '?';
    memcpy(
        stream_data->path + stream_data->pathlen - u->field_data[UF_QUERY].len,
        &uri[u->field_data[UF_QUERY].off], u->field_data[UF_QUERY].len);
  }

  return stream_data;
}

void delete_http2_stream_data(http2_stream_data *stream_data) {
  free(stream_data->path);
  free(stream_data->authority);
  free(stream_data);
}

/* Initializes |session_data| */
http2_session_data *create_http2_session_data(struct event_base *evbase) {
  http2_session_data *session_data = malloc(sizeof(http2_session_data));

  memset(session_data, 0, sizeof(http2_session_data));
  session_data->dnsbase = evdns_base_new(evbase, 1);
  return session_data;
}

void delete_http2_session_data(http2_session_data *session_data) {
  SSL *ssl = bufferevent_openssl_get_ssl(session_data->bev);

  if (ssl) {
    SSL_shutdown(ssl);
  }
  bufferevent_free(session_data->bev);
  session_data->bev = NULL;
  evdns_base_free(session_data->dnsbase, 1);
  session_data->dnsbase = NULL;
  nghttp2_session_del(session_data->session);
  session_data->session = NULL;
  if (session_data->stream.request_stream_data) {
    delete_http2_stream_data(session_data->stream.request_stream_data);
    session_data->stream.request_stream_data = NULL;
  }
  if (session_data->stream.ping_stream_data) {
    delete_http2_stream_data(session_data->stream.ping_stream_data);
    session_data->stream.ping_stream_data = NULL;
  }
  free(session_data);
}

void initialize_nghttp2_session(http2_session_data *session_data) {
  nghttp2_session_callbacks *callbacks;

  nghttp2_session_callbacks_new(&callbacks);

  nghttp2_session_callbacks_set_send_callback(callbacks, send_callback);

  nghttp2_session_callbacks_set_on_frame_recv_callback(callbacks,
                                                       on_frame_recv_callback);

  nghttp2_session_callbacks_set_on_data_chunk_recv_callback(
      callbacks, on_data_chunk_recv_callback);

  nghttp2_session_callbacks_set_on_stream_close_callback(
      callbacks, on_stream_close_callback);

  nghttp2_session_callbacks_set_on_header_callback(callbacks,
                                                   on_header_callback);

  nghttp2_session_callbacks_set_on_begin_headers_callback(
      callbacks, on_begin_headers_callback);

  nghttp2_session_client_new(&session_data->session, callbacks, session_data);

  nghttp2_session_callbacks_del(callbacks);
}

/* Serialize the frame and send (or buffer) the data to
   bufferevent. */
int session_send(http2_session_data *session_data) {
  int rv;

  rv = nghttp2_session_send(session_data->session);
  if (rv != 0) {
    warnx("Fatal error: %s", nghttp2_strerror(rv));
    return -1;
  }
  return 0;
}

int send_PING_frame(int CDN_id) {
  http2_session_data *session_data;
  session_data = CDN[CDN_id].session_data;
  CDN[CDN_id].RTT_updated = 0;
  gettimeofday(&CDN[CDN_id].ping_start, NULL);
  fprintf(stderr, "PING start from CDN %d \t", CDN_id);
  print_timeval(&CDN[CDN_id].ping_start);
  if (nghttp2_submit_ping(session_data->session, NGHTTP2_FLAG_NONE, NULL) <
      0) {
    report_error("ERROR: ping unsuccessfully!\n");
  }
  if (session_send(session_data) != 0) {
    delete_http2_session_data(session_data);
  }
}