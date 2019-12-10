/*
 * nghttp2 - HTTP/2 C Library
 *
 * Copyright (c) 2013 Tatsuhiro Tsujikawa
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 * LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 * OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 * WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
#ifdef __sgi
#include <string.h>
#define errx(exitcode, format, args...) \
  {                                     \
    warnx(format, ##args);              \
    exit(exitcode);                     \
  }
#define warnx(format, args...) fprintf(stderr, format "\n", ##args)
char *strndup(const char *s, size_t size);
#endif

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /* HAVE_CONFIG_H */

#include <sys/types.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif /* HAVE_UNISTD_H */
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif /* HAVE_SYS_SOCKET_H */
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif /* HAVE_NETINET_IN_H */
#include <netinet/tcp.h>
#ifndef __sgi
#include <err.h>
#endif
#include <getopt.h>
#include <signal.h>
#include <string.h>

#include <pthread.h>

#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

#include <event.h>
#include <event2/bufferevent_ssl.h>
#include <event2/dns.h>
#include <event2/event.h>

#include <nghttp2/nghttp2.h>

#include "callbacks.h"
#include "http2.h"
#include "ssl.h"
#include "url_parser.h"
#include "utils.h"

char file_path[500];
char output_file_path[500];
ssize_t chunk_size;

static void send_client_connection_header(http2_session_data *session_data) {
  nghttp2_settings_entry iv[1] = {
      {NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, 100}};
  int rv;
  /* client 24 bytes magic string will be sent by nghttp2 library */
  rv = nghttp2_submit_settings(session_data->session, NGHTTP2_FLAG_NONE, iv,
                               ARRLEN(iv));
  if (rv != 0) {
    errx(1, "Could not submit SETTINGS: %s", nghttp2_strerror(rv));
  }
}

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

nghttp2_nv *construct_header(http2_session_data *session_data, ssize_t st,
                             ssize_t en) {
  nghttp2_nv *hdrs;
  int s = 5;
  if (en == 0) {
    s = 4;
  }
  hdrs = (nghttp2_nv *)malloc(s * sizeof(nghttp2_nv));

  http2_stream_data *stream_data = session_data->stream.request_stream_data;

  const char *uri = stream_data->uri;
  const struct http_parser_url *u = stream_data->u;

  char buf[500];
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

/* Init request for each CDN */
static void submit_init_request(http2_session_data *session_data) {
  int CDN_id = session_data->CDN_id;
  int32_t stream_id;
  http2_stream_data *stream_data = session_data->stream.request_stream_data;
  const char *uri = stream_data->uri;
  const struct http_parser_url *u = stream_data->u;
  nghttp2_nv *hdrs;
  int num_hdrs;

  stream_data->buf_ptr = global_data_buf + content_size / 3 * CDN_id;
  stream_data->st = content_size / 3 * CDN_id;
  stream_data->en = content_size / 3 * (CDN_id + 1);
  if (CDN_id == 2) stream_data->en = content_size;
  stream_data->received_bytes = 0;

  if (CDN_id == 0) {
    hdrs = construct_header(session_data, 0, 0);
    num_hdrs = 4;
  } else {
    hdrs = construct_header(session_data, stream_data->st, stream_data->en);
    num_hdrs = 5;
  }

  fprintf(stderr, "Request headers at CDN %d:\n", CDN_id);
  print_headers(stderr, hdrs, ARRLEN(hdrs));

  stream_id = nghttp2_submit_request(session_data->session, NULL, hdrs,
                                     num_hdrs, NULL, stream_data);

  if (stream_id < 0) {
    errx(1, "Could not submit HTTP request: %s", nghttp2_strerror(stream_id));
  }

  stream_data->stream_id = stream_id;

  free(hdrs);
}

/* readcb for bufferevent. Here we get the data from the input buffer
   of bufferevent and feed them to nghttp2 library. This may invoke
   nghttp2 callbacks. It may also queues the frame in nghttp2 session
   context. To send them, we call session_send() in the end. */
static void readcb(struct bufferevent *bev, void *ptr) {
  http2_session_data *session_data = (http2_session_data *)ptr;
  ssize_t readlen;
  struct evbuffer *input = bufferevent_get_input(bev);
  size_t datalen = evbuffer_get_length(input);
  unsigned char *data = evbuffer_pullup(input, -1);

  readlen = nghttp2_session_mem_recv(session_data->session, data, datalen);
  if (readlen < 0) {
    warnx("Fatal error: %s", nghttp2_strerror((int)readlen));
    delete_http2_session_data(session_data);
    return;
  }
  if (evbuffer_drain(input, (size_t)readlen) != 0) {
    warnx("Fatal error: evbuffer_drain failed");
    delete_http2_session_data(session_data);
    return;
  }
  if (session_send(session_data) != 0) {
    delete_http2_session_data(session_data);
    return;
  }
}

/* writecb for bufferevent. To greaceful shutdown after sending or
   receiving GOAWAY, we check the some conditions on the nghttp2
   library and output buffer of bufferevent. If it indicates we have
   no business to this session, tear down the connection. */
static void writecb(struct bufferevent *bev, void *ptr) {
  http2_session_data *session_data = (http2_session_data *)ptr;
  (void)bev;

  if (nghttp2_session_want_read(session_data->session) == 0 &&
      nghttp2_session_want_write(session_data->session) == 0 &&
      evbuffer_get_length(bufferevent_get_output(session_data->bev)) == 0) {
    delete_http2_session_data(session_data);
  }
}

/* eventcb for bufferevent. For the purpose of simplicity and
   readability of the example program, we omitted the certificate and
   peer verification. After SSL/TLS handshake is over, initialize
   nghttp2 library session, and send client connection header. Then
   send HTTP request. */
static void eventcb(struct bufferevent *bev, short events, void *ptr) {
  http2_session_data *session_data = (http2_session_data *)ptr;
  int CDN_id;
  CDN_id = CDN_lookup(session_data);

  if (events & BEV_EVENT_CONNECTED) {
    int fd = bufferevent_getfd(bev);
    int val = 1;
    const unsigned char *alpn = NULL;
    unsigned int alpnlen = 0;
    SSL *ssl;

    fprintf(stderr, "Connected CDN %d\n", CDN_id);

    ssl = bufferevent_openssl_get_ssl(session_data->bev);

#ifndef OPENSSL_NO_NEXTPROTONEG
    SSL_get0_next_proto_negotiated(ssl, &alpn, &alpnlen);
#endif /* !OPENSSL_NO_NEXTPROTONEG */
#if OPENSSL_VERSION_NUMBER >= 0x10002000L
    if (alpn == NULL) {
      SSL_get0_alpn_selected(ssl, &alpn, &alpnlen);
    }
#endif /* OPENSSL_VERSION_NUMBER >= 0x10002000L */

    if (alpn == NULL || alpnlen != 2 || memcmp("h2", alpn, 2) != 0) {
      fprintf(stderr, "h2 is not negotiated\n");
      delete_http2_session_data(session_data);
      return;
    }

    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (char *)&val, sizeof(val));
    initialize_nghttp2_session(session_data);

    /* printf("[DEBUG] session data address: %x\n", CDN[0].session_data);
    printf("[DEBUG] session address: %x\n", CDN[0].session_data->session); */

    send_client_connection_header(session_data);

    send_PING_frame(CDN_id);

    submit_init_request(session_data);
    if (session_send(session_data) != 0) {
      delete_http2_session_data(session_data);
    }

    return;
  }
  if (events & BEV_EVENT_EOF) {
    // warnx("Disconnected from the remote host");
    return;
  } else if (events & BEV_EVENT_ERROR) {
    warnx("Network error");
  } else if (events & BEV_EVENT_TIMEOUT) {
    warnx("Timeout");
  }
  delete_http2_session_data(session_data);
}

/* Start connecting to the remote peer |host:port| */
static void initiate_connection(struct event_base *evbase, SSL_CTX *ssl_ctx,
                                const char *host, uint16_t port,
                                http2_session_data *session_data) {
  int rv;
  struct bufferevent *bev;
  SSL *ssl;

  ssl = create_ssl(ssl_ctx);
  bev = bufferevent_openssl_socket_new(
      evbase, -1, ssl, BUFFEREVENT_SSL_CONNECTING,
      BEV_OPT_DEFER_CALLBACKS | BEV_OPT_CLOSE_ON_FREE);
  bufferevent_enable(bev, EV_READ | EV_WRITE);
  bufferevent_setcb(bev, readcb, writecb, eventcb, session_data);
  rv = bufferevent_socket_connect_hostname(bev, session_data->dnsbase,
                                           AF_UNSPEC, host, port);

  if (rv != 0) {
    errx(1, "Could not connect to the remote host %s", host);
  }
  session_data->bev = bev;
}

void init_CDN(int CDN_id) {
  /* Parse the |uri| and stores its components in |u| */
  int rv;
  rv = http_parser_parse_url(CDN[CDN_id].url, strlen(CDN[CDN_id].url), 0,
                             &CDN[CDN_id].u);
  if (rv != 0) {
    errx(1, "Could not parse URI %s", CDN[CDN_id].url);
  }

  CDN[CDN_id].RTT_updated = 1;

  CDN[CDN_id].host =
      strndup(&CDN[CDN_id].url[CDN[CDN_id].u.field_data[UF_HOST].off],
              CDN[CDN_id].u.field_data[UF_HOST].len);
  if (!(CDN[CDN_id].u.field_set & (1 << UF_PORT))) {
    CDN[CDN_id].port = 443;
  } else {
    CDN[CDN_id].port = CDN[CDN_id].u.port;
  }

  CDN[CDN_id].ssl_ctx = create_ssl_ctx();

  CDN[CDN_id].evbase = event_base_new();

  CDN[CDN_id].session_data = create_http2_session_data(CDN[CDN_id].evbase);
  CDN[CDN_id].session_data->CDN_id = CDN_id;
  CDN[CDN_id].session_data->stream.request_stream_data =
      create_http2_stream_data(CDN[CDN_id].url, &CDN[CDN_id].u);

  initiate_connection(CDN[CDN_id].evbase, CDN[CDN_id].ssl_ctx, CDN[CDN_id].host,
                      CDN[CDN_id].port, CDN[CDN_id].session_data);

  free(CDN[CDN_id].host);
  CDN[CDN_id].host = NULL;
}

/* Get resource denoted by the |uri|. The debug and error messages are
   printed in stderr, while the response body is printed in stdout. */
void *run(void *id) {
  int CDN_id;

  CDN_id = (int)id;

  /*printf("[DEBUG] session data address: %x\n", CDN[CDN_id].session_data);
  printf("[DEBUG] session address: %x\n", CDN[CDN_id].session_data->session);*/

  // Waiting for the content size
  while (CDN_id > 0 && content_size <= 0)
    ;

  event_base_loop(CDN[CDN_id].evbase, 0);

  event_base_free(CDN[CDN_id].evbase);
  SSL_CTX_free(CDN[CDN_id].ssl_ctx);
}

static void usage(const char *progname) {
  fprintf(stderr,
          "Usage: %s [options] <url>\n"
          "Options:\n"
          "  -c <size>    size of body chunk (in bytes; default: 10)\n"
          "  -o <path>    file to which the response body is written (default: "
          "stdout)\n"
          "  -t <file path>\n"
          "               the path of the file for download\n"
          "  -h           prints this help\n"
          "\n",
          progname);
}

int main(int argc, char **argv) {
  struct sigaction act;

  // Parser input command parameters
  int opt;
  while ((opt = getopt(argc, argv, "T:t:o:c:k2:h")) != -1) {
    int8_t ratio;
    switch (opt) {
      case 't':
        strcpy(file_path, optarg);
        // printf("[DEBUG] The absolute path of the file for download: %s\n",
        //        file_path);
        break;
      case 'o':
        strcpy(output_file_path, optarg);
        printf("[DEBUG] Output file path: %s\n", output_file_path);
        break;
      case 'c':
        chunk_size = atoi(optarg);
        if (chunk_size <= 0) {
          fprintf(stderr, "chunk size must be greater than 0\n");
          exit(EXIT_FAILURE);
        }
        break;
      case 'h':
        usage(argv[0]);
        exit(0);
        break;
      default:
        exit(EXIT_FAILURE);
        break;
    }
  }
  argc -= optind;
  argv += optind;

  if (argc != CDN_NUM) {
    fprintf(stderr,
            "Current version only supports %d multi-paths! Please provide "
            "exactly %d URLs for CDNs\n",
            CDN_NUM, CDN_NUM);
    exit(EXIT_FAILURE);
  }

  SSL_load_error_strings();
  SSL_library_init();

  content_size = 0;
  for (int i = 0; i < CDN_NUM; ++i) {
    strncpy(CDN[i].url, argv[i], strlen(argv[i]));
    strncat(CDN[i].url, file_path, strlen(file_path));
    init_CDN(i);
  }

  memset(&act, 0, sizeof(struct sigaction));
  act.sa_handler = SIG_IGN;
  sigaction(SIGPIPE, &act, NULL);

  for (int i = 0; i < CDN_NUM; ++i) {
    if (pthread_create(&CDN[i].tid, NULL, run, i) < 0) {
      fprintf(stderr, "ERROR in creating thread for CDN %d\n", i);
      exit(EXIT_FAILURE);
    }
  }

  for (int i = 0; i < CDN_NUM; ++i) {
    pthread_join(CDN[i].tid, NULL);
  }

  FILE *outputfile;
  outputfile = fopen(output_file_path, "w+");
  fwrite(global_data_buf, 1, content_size, outputfile);
  fclose(outputfile);

  return 0;
}