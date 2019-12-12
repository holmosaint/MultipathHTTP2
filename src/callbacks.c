#include <string.h>

#include <event.h>
#include <event2/bufferevent_ssl.h>
#include <event2/dns.h>
#include <event2/event.h>

#include <nghttp2/nghttp2.h>

#include "http2.h"
#include "utils.h"

/* nghttp2_on_frame_recv_callback: Called when nghttp2 library
   received a complete frame from the remote peer. */
int on_frame_recv_callback(nghttp2_session *session, const nghttp2_frame *frame,
                           void *user_data) {
  http2_session_data *session_data = (http2_session_data *)user_data;
  (void)session;

  int CDN_id;

  /* We only consider main stream for PING as well as print headers */
  switch (frame->hd.type) {
    case NGHTTP2_HEADERS:
      if (frame->headers.cat == NGHTTP2_HCAT_RESPONSE &&
          session_data->stream.request_stream_data->stream_id ==
              frame->hd.stream_id) {
        fprintf(stderr, "All headers received\n");
      }
      break;
    case NGHTTP2_PING:
      // printf("[DEBUG]Received PING frame!\n");
      CDN_id = CDN_lookup(session_data);
      if (CDN_id < 0) {
        char buf[500];
        printf("------------[DEBUG]------------\n");
        for (int i = 0; i < CDN_NUM; ++i) {
          print_CDN_info(i);
        }
        sprintf(buf, "ERROR: cannot find CDN by session address: 0x%x\n",
                session);
        report_error(buf);
      }
      struct timeval ping_end;
      double RTT;
      gettimeofday(&ping_end, NULL);
      // print_timeval(&ping_end);
      if (CDN[CDN_id].ping_start.tv_sec == 0 &&
          CDN[CDN_id].ping_start.tv_usec == 0) {
        break;
      }
      RTT = (double)(ping_end.tv_sec - CDN[CDN_id].ping_start.tv_sec) +
            (double)(ping_end.tv_usec - CDN[CDN_id].ping_start.tv_usec) / 1e6;
      // Update RTT time
      if (CDN[CDN_id].RTT < 0) {
        CDN[CDN_id].RTT = RTT;
      } else {
        CDN[CDN_id].RTT = CDN[CDN_id].RTT * 0.3 + RTT * 0.7;
      }
      // printf("Estimated RTT time: %.3fs\n", CDN[CDN_id].RTT);
      CDN[CDN_id].ping_start.tv_sec = 0;
      CDN[CDN_id].ping_start.tv_usec = 0;
      CDN[CDN_id].RTT_updated = 1;

      // Send another PING frame
      send_PING_frame(CDN_id);
  }
  return 0;
}

/* nghttp2_on_data_chunk_recv_callback: Called when DATA frame is
   received from the remote peer. In this implementation, if the frame
   is meant to the stream we initiated, print the received data in
   stdout, so that the user can redirect its output to the file
   easily. */
int on_data_chunk_recv_callback(nghttp2_session *session, uint8_t flags,
                                int32_t stream_id, const uint8_t *data,
                                size_t len, void *user_data) {
  http2_session_data *session_data = (http2_session_data *)user_data;
  http2_stream_data *stream_data;
  int CDN_id = session_data->CDN_id;
  (void)session;
  (void)flags;

  /* printf("-------------------\n");
  printf("[DEBUG] Recieved Stream ID %d for CDN %d\n", stream_id, CDN_id);
  printf("-------------------\n");
  printf("Received Length: %lu\n", len); */

  pthread_mutex_lock(&session_data->session_mutex);
  if (session_data->stream.request_stream_data->stream_id == stream_id) {
    // fwrite(data, 1, len, stdout);
    stream_data = session_data->stream.request_stream_data;
  } else if (session_data->stream.extra_request_stream_data->stream_id ==
             stream_id) {
    stream_data = session_data->stream.extra_request_stream_data;
  } else {
    pthread_mutex_unlock(&session_data->session_mutex);
    return 0;
  }

  fwrite(data, 1, len, stream_data->stream_file);

  pthread_mutex_lock(&global_mutex);
  if (stream_data->received_bytes < stream_data->en - stream_data->st + 1) {
    if (len + stream_data->received_bytes >=
        stream_data->en - stream_data->st + 1) {
      estimated_total_content_left -=
          (stream_data->en - stream_data->st + 1) - stream_data->received_bytes;
    } else {
      estimated_total_content_left -= len;
    }
  }
  pthread_mutex_unlock(&global_mutex);

  /*if(CDN_id == 0) {
    fprintf(stderr, "+++++++++++Received %luB in stream %d CDN %d\n", len,
  stream_id, CDN_id); fprintf(stderr, "Content left: %lu\n",
  estimated_total_content_left); fflush(stderr);
  }*/

  stream_data->received_bytes += len;
  gettimeofday(&stream_data->en_time, NULL);

  if (stream_data->received_bytes >= stream_data->en - stream_data->st + 1) {
    /* if(stream_data) {
      delete_http2_stream_data(stream_data);
      stream_data = NULL;
    } */
    /* fprintf(
        stderr, "[DEBUG] received bytes from CDN %d: %lu, st: %lu, en: %lu\n",
        CDN_id, stream_data->received_bytes, stream_data->st, stream_data->en);
     */
    if (nghttp2_submit_rst_stream(session_data->session, NGHTTP2_FLAG_NONE,
                                  stream_id, 0) != 0) {
      report_error("ERROR in sending rst frame!\n");
    }

    stream_data->end_flag = STREAM_END;
  }

  pthread_mutex_unlock(&session_data->session_mutex);

  pthread_mutex_lock(&CDN[CDN_id].CDN_mutex);
  struct timeval tmp_time;
  gettimeofday(&tmp_time, NULL);
  double duration = 0;
  duration = (double)(tmp_time.tv_sec - stream_data->st_time.tv_sec) +
             (double)(tmp_time.tv_usec - stream_data->st_time.tv_usec) * 1e-6;
  CDN[CDN_id].BW = stream_data->received_bytes / duration;
  pthread_mutex_unlock(&CDN[CDN_id].CDN_mutex);

  // global_schedule(CDN_id);

  return 0;
}

/* nghttp2_on_stream_close_callback: Called when a stream is about to
   closed. This example program only deals with 1 HTTP request (1
   stream), if it is closed, we send GOAWAY and tear down the
   session */
int on_stream_close_callback(nghttp2_session *session, int32_t stream_id,
                             uint32_t error_code, void *user_data) {
  http2_session_data *session_data = (http2_session_data *)user_data;
  http2_stream_data *stream_data;
  int rv;
  char buf[500];
  int CDN_id = session_data->CDN_id;

  pthread_mutex_lock(&session_data->session_mutex);
  if (session_data->stream.request_stream_data->stream_id == stream_id) {
    stream_data = session_data->stream.request_stream_data;
  } else if (session_data->stream.extra_request_stream_data->stream_id ==
             stream_id) {
    stream_data = session_data->stream.extra_request_stream_data;
    session_data->stream.extra_request_stream_data =
        session_data->stream.request_stream_data;
    session_data->stream.request_stream_data = stream_data;
  } else {
    pthread_mutex_unlock(&session_data->session_mutex);
    return 0;
  }

  pthread_mutex_lock(&global_mutex);
  printf("====================Content received %luB\n",
         stream_data->en - stream_data->st + 1);
  printf("Total content left: %lu\n", total_content_left);
  total_content_left -= (stream_data->en - stream_data->st + 1);
  pthread_mutex_unlock(&global_mutex);

  fflush(stream_data->stream_file);
  stream_data->end_flag = STREAM_END;

  pthread_mutex_unlock(&session_data->session_mutex);

  fprintf(stderr, "Stream %d closed with error_code=%u\n", stream_id,
          error_code);

  sprintf(buf, "%lu-%lu %lu-%lu %lu\n", stream_data->st,
          stream_data->st_time.tv_sec, stream_data->st_time.tv_usec,
          stream_data->en_time.tv_sec, stream_data->en_time.tv_usec);

  pthread_mutex_lock(&CDN[CDN_id].CDN_mutex);
  fwrite(buf, 1, strlen(buf), CDN[CDN_id].range_file);
  fflush(CDN[CDN_id].range_file);
  pthread_mutex_unlock(&CDN[CDN_id].CDN_mutex);

  // global_schedule(CDN_id);

  return 0;
}

/* nghttp2_send_callback. Here we transmit the |data|, |length| bytes,
   to the network. Because we are using libevent bufferevent, we just
   write those bytes into bufferevent buffer. */
ssize_t send_callback(nghttp2_session *session, const uint8_t *data,
                      size_t length, int flags, void *user_data) {
  http2_session_data *session_data = (http2_session_data *)user_data;
  struct bufferevent *bev = session_data->bev;
  (void)session;
  (void)flags;

  bufferevent_write(bev, data, length);
  return (ssize_t)length;
}

/* nghttp2_on_header_callback: Called when nghttp2 library emits
   single header name/value pair. */
int on_header_callback(nghttp2_session *session, const nghttp2_frame *frame,
                       const uint8_t *name, size_t namelen,
                       const uint8_t *value, size_t valuelen, uint8_t flags,
                       void *user_data) {
  http2_session_data *session_data = (http2_session_data *)user_data;
  (void)session;
  (void)flags;

  char buf[500];

  /* Consider only the main stream for content size */
  switch (frame->hd.type) {
    case NGHTTP2_HEADERS:
      if (frame->headers.cat == NGHTTP2_HCAT_RESPONSE &&
          session_data->stream.request_stream_data->stream_id ==
              frame->hd.stream_id) {
        /* Print response headers for the initiated request. */
        print_header(stderr, name, namelen, value, valuelen);

        if (content_size <= 0) {
          // Extrat header to get content size
          for (ssize_t i = 0; i < namelen; ++i) {
            buf[i] = (char)(name[i]);
          }
          buf[namelen] = '\0';

          if (strncmp(buf, "content-length", namelen) == 0) {
            for (ssize_t i = 0; i < valuelen; ++i) {
              buf[i] = (char)(value[i]);
            }
            buf[valuelen] = '\0';
            estimated_total_content_left = atoi(buf);
            total_content_left = estimated_total_content_left;
            content_size = estimated_total_content_left;
            // printf("[DEBUG] change end to %lu\n", content_size / 3);
            change_stream_end(0, content_size / 3);
            printf("[DEBUG] Get content size: %lu\n", content_size);
          }
        }
        break;
      }
  }
  return 0;
}

/* nghttp2_on_begin_headers_callback: Called when nghttp2 library gets
   started to receive header block. */
int on_begin_headers_callback(nghttp2_session *session,
                              const nghttp2_frame *frame, void *user_data) {
  http2_session_data *session_data = (http2_session_data *)user_data;
  (void)session;

  switch (frame->hd.type) {
    case NGHTTP2_HEADERS:
      if (frame->headers.cat == NGHTTP2_HCAT_RESPONSE &&
          session_data->stream.request_stream_data->stream_id ==
              frame->hd.stream_id) {
        fprintf(stderr, "Response headers for stream ID=%d:\n",
                frame->hd.stream_id);
      }
      break;
  }
  return 0;
}