#include <stdint.h>
#include <sys/types.h>

#include <event.h>
#include <event2/bufferevent_ssl.h>
#include <event2/dns.h>
#include <event2/event.h>

#include <nghttp2/nghttp2.h>

#include "http2.h"

void print_header(FILE *f, const uint8_t *name, size_t namelen,
                  const uint8_t *value, size_t valuelen) {
  fwrite(name, 1, namelen, f);
  fprintf(f, ": ");
  fwrite(value, 1, valuelen, f);
  fprintf(f, "\n");
}

/* Print HTTP headers to |f|. Please note that this function does not
   take into account that header name and value are sequence of
   octets, therefore they may contain non-printable characters. */
void print_headers(FILE *f, nghttp2_nv *nva, size_t nvlen) {
  size_t i;
  for (i = 0; i < nvlen; ++i) {
    print_header(f, nva[i].name, nva[i].namelen, nva[i].value, nva[i].valuelen);
  }
  fprintf(f, "\n");
}

void report_error(char *error_msg) {
  fprintf(stderr, error_msg);
  fflush(stderr);
  exit(1);
}

void print_CDN_info(int id) {
  printf("Info of CDN %d\n", id);
  printf("\tRTT: %.3lfs\n", CDN[id].RTT);
  printf("\tBW: %.3lfs\n", CDN[id].BW);
  printf("\tbghttp2_session address: 0x%x\n", CDN[id].session_data->session);
  printf("\thost: %s\n", CDN[id].host);
  printf("\tport: %hu\n", CDN[id].port);
}

void print_timeval(struct timeval *t) {
  printf("%ld.%.6lds\n", t->tv_sec, t->tv_usec);
}

