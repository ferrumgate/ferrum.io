#include "ferrum/ferrum.h"
#include "ferrum/ferrum_redis.h"
#include "ferrum/ferrum_config.h"

// compiler unused function problem
static const void *nouse = redisLibuvAttach;

void close_cb(uv_handle_t *handle) {
  unused(handle);
  unused(nouse);
  uv_stop(uv_default_loop());
}

static void on_data_received(rebrick_socket_t *socket, void *data, const struct sockaddr *addr, const uint8_t *buffer, ssize_t len) {
  unused(addr);
  unused(socket);
  new2(rebrick_conntrack_t, track);

  rebrick_conntrack_get(addr, &socket->bind_addr.base, 0, &track);
}

void signal_cb(uv_signal_t *handle, int signum) {

  unused(signum);
  uv_signal_stop(handle);
  /*  rebrick_listener_t *listener = cast(handle->data, rebrick_listener_t *);
   rebrick_crontab_destroy(crontab); */
  uv_sleep(100);

  ferrum_log_warn("ctrl+break detected, shutting down\n");
  uv_close(cast(handle, uv_handle_t *), close_cb);
}

int main() {
  ferrum_log_warn("current version: %s\n", FERRUM_VERSION);
  int32_t result;

  ferrum_config_t *config;
  result = ferrum_config_new(&config);
  if (result) {
    ferrum_log_fatal("config create failed:%d\n", result);
    rebrick_kill_current_process(result);
  }
  if (config->raw.dest_tcp_port || config->raw.dest_udp_port) {
  }

  rebrick_udpsocket_t *udp = NULL;
  rebrick_sockaddr_t addr;
  rebrick_util_ip_port_to_addr("192.168.88.10", "9090", &addr);
  new2(rebrick_udpsocket_callbacks_t, callbacks);
  callbacks.on_read = on_data_received;
  result = rebrick_udpsocket_new(&udp, &addr, &callbacks);

  // capture ctrl+c
  uv_signal_t ctrl_c;
  uv_signal_init(uv_default_loop(), &ctrl_c);
  // ctrl_c.data = listener;
  uv_signal_start(&ctrl_c, signal_cb, SIGINT);

  //////////////////////////////////
  uv_run(uv_default_loop(), UV_RUN_DEFAULT);
  uv_loop_close(uv_default_loop());
  return 0;
}