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
#include "utils.h"

nghttp2_nv *construct_header(http2_stream_data *stream_data, ssize_t st,
                             ssize_t en) {
  char buf[500];

  nghttp2_nv *hdrs;
  int s = 5;
  if (en == 0) {
    s = 4;
  }
  hdrs = (nghttp2_nv *)malloc(s * sizeof(nghttp2_nv));

  const char *uri = stream_data->uri;
  const struct http_parser_url *u = stream_data->u;

  sprintf(buf, "bytes=%lu-%lu", st, en);

  if (s == 4) {
    nghttp2_nv tmp_hdrs[] = {
        MAKE_NV2(":method", "GET"),
        MAKE_NV(":scheme", &uri[u->field_data[UF_SCHEMA].off],
                u->field_data[UF_SCHEMA].len),
        MAKE_NV(":authority", stream_data->authority,
                stream_data->authoritylen),
        MAKE_NV(":path", stream_data->path, stream_data->pathlen)};
    for (int i = 0; i < s; ++i) {
      memcpy(&hdrs[i], &tmp_hdrs[i], sizeof(nghttp2_nv));
    }
  } else {
    nghttp2_nv tmp_hdrs[] = {
        MAKE_NV2(":method", "GET"),
        MAKE_NV(":scheme", &uri[u->field_data[UF_SCHEMA].off],
                u->field_data[UF_SCHEMA].len),
        MAKE_NV(":authority", stream_data->authority,
                stream_data->authoritylen),
        MAKE_NV(":path", stream_data->path, stream_data->pathlen),
        MAKE_NV("range", buf, strlen(buf))};
    for (int i = 0; i < s; ++i) {
      memcpy(&hdrs[i], &tmp_hdrs[i], sizeof(nghttp2_nv));
    }
  }

  return hdrs;
}

void submit_request_stream(http2_session_data *session_data,
                           http2_stream_data *stream_data, ssize_t st,
                           ssize_t en, int num_hdrs) {
  int CDN_id = session_data->CDN_id;
  int32_t stream_id;
  const char *uri = stream_data->uri;
  const struct http_parser_url *u = stream_data->u;
  nghttp2_nv *hdrs;
  char buf[500];

  stream_data->st = st;
  stream_data->en = en;
  stream_data->received_bytes = 0;
  sprintf(buf, "%lu.txt", stream_data->st);
  stream_data->stream_file = fopen(buf, "w+");
  if (stream_data->stream_file == NULL) {
    fprintf(stderr, "ERROR in creating output file [%s] for stream at CDN %d\n",
            buf, CDN_id);
  }

  hdrs = construct_header(stream_data, st, en);

  fprintf(stderr, "Request headers at CDN %d:\n", CDN_id);
  print_headers(stderr, hdrs, num_hdrs);

  gettimeofday(&stream_data->st_time, NULL);
  stream_id = nghttp2_submit_request(session_data->session, NULL, hdrs,
                                     num_hdrs, NULL, stream_data);
  // printf("[DEBUG] Stream ID %d from CDN %d\n", stream_id, CDN_id);
  if (stream_id < 0) {
    errx(1, "Could not submit HTTP request: %s", nghttp2_strerror(stream_id));
  }

  stream_data->stream_id = stream_id;

  free(hdrs);
}

/* Init request for each CDN */
void submit_init_request(http2_session_data *session_data) {
  int CDN_id = session_data->CDN_id;
  http2_stream_data *stream_data = session_data->stream.request_stream_data;
  int num_hdrs;
  char buf[50];
  ssize_t st, en;

  st = content_size / 3 * CDN_id;
  en = content_size / 3 * (CDN_id + 1);
  if (CDN_id == 2) stream_data->en = content_size;

  if (CDN_id == 0) {
    en = 0;
    num_hdrs = 4;
  } else {
    num_hdrs = 5;
  }

  submit_request_stream(session_data, stream_data, st, en, num_hdrs);
}

void change_stream_end(int CDN_id, ssize_t new_en) {
  http2_stream_data *stream_data;
  stream_data = CDN[CDN_id].session_data->stream.request_stream_data;

  pthread_mutex_lock(&stream_data->stream_mutex);
  stream_data->en = new_en;
  pthread_mutex_unlock(&stream_data->stream_mutex);
}

/* Calculate content size for each CDN */
void cal_content_size(ssize_t *D) {
  double BW, BW_RTT, coe;
  BW = 0;
  BW_RTT = 0;
  coe = 0;

  for (int i = 0; i < CDN_NUM; ++i) {
    BW += CDN[i].BW;
    BW_RTT += CDN[i].BW * CDN[i].RTT;
  }
  coe = (BW_RTT + estimated_total_content_left) / BW;

  for (int i = 0; i < CDN_NUM; ++i) {
    D[i] = CDN[i].BW * coe - CDN[i].BW * CDN[i].RTT;
  }
}

/* Schdule Stream*/
int schedule_stream(int CDN_id, http2_stream_data **stream_data) {
  int rv;
  ssize_t st, en;

  // Create a new stream
  // *stream_data = create_http2_stream_data(CDN[CDN_id].url, &CDN[CDN_id].u);

  ssize_t *D;
  D = (int *)calloc(CDN_NUM, sizeof(ssize_t));
  if (D == NULL) {
    report_error("ERROR in calloc for schedule!\n");
  }
  cal_content_size(D);

  for (int i = 0; i < CDN_NUM; ++i) {
    if (D[i] < CHUNK_SIZE) return GLOBAL_CHUNK_THRE;
  }

  ssize_t L, R, choice;
  L = (CDN_id - 1 + CDN_NUM) % CDN_NUM;
  R = (CDN_id + 1 + CDN_NUM) % CDN_NUM;

  if (D[L] > D[R])
    choice = R;
  else
    choice = L;

  st = CDN[choice].session_data->stream.request_stream_data->en - D[CDN_id];
  en = CDN[choice].session_data->stream.request_stream_data->en;
  if (st <=
      CDN[choice].session_data->stream.request_stream_data->st +
          CDN[choice].session_data->stream.request_stream_data->received_bytes -
          CHUNK_SIZE) {
    return GLOBAL_CHUNK_THRE;
  }

  printf("-----------------[DEBUG]-----------------\n");
  printf("New end for CDN %d is: %lu.\n", CDN_id, en);

  change_stream_end(choice, st - 1);

  (*stream_data)->end_flag = 0;
  submit_request_stream(CDN[CDN_id].session_data, *stream_data, st, en, 5);

  printf("Schedule from CDN %d\n", CDN_id);
  for (int i = 0; i < CDN_NUM; ++i) {
    printf("CDN %d: %lu-%lu\t", i,
           CDN[i].session_data->stream.request_stream_data->st,
           CDN[i].session_data->stream.request_stream_data->en);
  }

  printf("CDN %d: %lu-%lu\t", CDN_id,
         CDN[CDN_id].session_data->stream.extra_request_stream_data->st,
         CDN[CDN_id].session_data->stream.extra_request_stream_data->en);

  printf("\n");
  printf("-----------------[DEBUG]-----------------\n");
  printf("\n");

  free(D);

  return GLOBAL_SCHE_SUCC;
}

/* Global Scheduler */
int global_schedule(int CDN_id) {
  // printf("[DEBUG] Scheduling CDN %d\n", CDN_id);
  // Only schedule when there are less than 2 streams
  if ((!(CDN[CDN_id].session_data->stream.request_stream_data->end_flag &
       STREAM_END)) &&
      (!(CDN[CDN_id].session_data->stream.extra_request_stream_data->end_flag &
       STREAM_END))) {
    return GLOBAL_SCHE_NO_EMPTY_STREAM;
  }

  /* Make sure extra stream on extra stream */
  if (CDN[CDN_id].session_data->stream.request_stream_data->end_flag &
      STREAM_END) {
    pthread_mutex_lock(&CDN[CDN_id].session_data->session_mutex);
    http2_stream_data *tmp_stream;
    tmp_stream = CDN[CDN_id].session_data->stream.extra_request_stream_data;
    CDN[CDN_id].session_data->stream.extra_request_stream_data =
        CDN[CDN_id].session_data->stream.request_stream_data;
    CDN[CDN_id].session_data->stream.request_stream_data = tmp_stream;
    pthread_mutex_unlock(&CDN[CDN_id].session_data->session_mutex);
  }

  /* Estimation of finishing time */
  ssize_t st, en, received;
  st = CDN[CDN_id].session_data->stream.request_stream_data->st;
  en = CDN[CDN_id].session_data->stream.request_stream_data->en;
  received =
      CDN[CDN_id].session_data->stream.request_stream_data->received_bytes;
  if (CDN[CDN_id].RTT < (en - st - received) / CDN[CDN_id].BW)
    return GLOBAL_SCHE_EARLY;

  if (CDN_alive != CDN_NUM) return GLOBAL_LACK_CDN;

  return schedule_stream(
      CDN_id, &CDN[CDN_id].session_data->stream.extra_request_stream_data);
}

/* Look up CDN id by session address*/
int CDN_lookup(http2_session_data *session_data) {
  return session_data->CDN_id;
}

http2_stream_data *create_http2_stream_data(const char *uri,
                                            struct http_parser_url *u) {
  /* MAX 5 digits (max 65535) + 1 ':' + 1 NULL (because of snprintf) */
  size_t extra = 7;
  http2_stream_data *stream_data =
      (http2_stream_data *)malloc(sizeof(http2_stream_data));

  stream_data->uri = uri;
  stream_data->u = u;
  stream_data->stream_id = -1;
  pthread_mutex_init(&stream_data->stream_mutex, NULL);

  stream_data->authoritylen = u->field_data[UF_HOST].len;
  stream_data->authority = (char *)malloc(stream_data->authoritylen + extra);
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

  stream_data->path = (char *)malloc(stream_data->pathlen);
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
  pthread_mutex_destroy(&stream_data->stream_mutex);
  fclose(stream_data->stream_file);
  free(stream_data->path);
  free(stream_data->authority);
  free(stream_data);
  stream_data = NULL;
}

/* Initializes |session_data| */
http2_session_data *create_http2_session_data(struct event_base *evbase) {
  http2_session_data *session_data =
      (http2_session_data *)malloc(sizeof(http2_session_data));

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
  if (session_data->stream.extra_request_stream_data) {
    delete_http2_stream_data(session_data->stream.extra_request_stream_data);
    session_data->stream.extra_request_stream_data = NULL;
  }
  pthread_mutex_destroy(&session_data->session_mutex);
  free(session_data);
}

void initialize_nghttp2_session(http2_session_data *session_data) {
  pthread_mutex_init(&session_data->session_mutex, NULL);

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
    fprintf(stderr, "Fatal error: %s", nghttp2_strerror(rv));
    return -1;
  }
  return 0;
}

int send_PING_frame(int CDN_id) {
  http2_session_data *session_data;
  session_data = CDN[CDN_id].session_data;
  CDN[CDN_id].RTT_updated = 0;
  gettimeofday(&CDN[CDN_id].ping_start, NULL);
  // fprintf(stderr, "PING start from CDN %d \t", CDN_id);
  // print_timeval(&CDN[CDN_id].ping_start);
  if (nghttp2_submit_ping(session_data->session, NGHTTP2_FLAG_NONE, NULL) < 0) {
    report_error("ERROR: ping unsuccessfully!\n");
  }
  if (session_send(session_data) != 0) {
    delete_http2_session_data(session_data);
  }
}