#include <stdint.h>
#include <sys/types.h>

#include <event.h>
#include <event2/bufferevent_ssl.h>
#include <event2/dns.h>
#include <event2/event.h>

#include <nghttp2/nghttp2.h>

#ifndef UTILS
#define UTILS

void print_header(FILE *f, const uint8_t *name, size_t namelen,
                  const uint8_t *value, size_t valuelen);

/* Print HTTP headers to |f|. Please note that this function does not
   take into account that header name and value are sequence of
   octets, therefore they may contain non-printable characters. */
void print_headers(FILE *f, nghttp2_nv *nva, size_t nvlen);

void report_error(char *error_msg);

void print_CDN_info(int id);

void print_timeval(struct timeval *t);

#endif
