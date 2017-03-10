
#include "ares_setup.h"

#ifdef HAVE_NETINET_IN_H
#  include <netinet/in.h>
#endif
#ifdef HAVE_ARPA_INET_H
#  include <arpa/inet.h>
#endif
#ifdef HAVE_NETDB_H
#  include <netdb.h>
#endif
#ifdef HAVE_ARPA_NAMESER_H
#  include <arpa/nameser.h>
#else
#  include "nameser.h"
#endif
#ifdef HAVE_ARPA_NAMESER_COMPAT_H
#  include <arpa/nameser_compat.h>
#endif

#ifdef HAVE_STRINGS_H
#  include <strings.h>
#endif

#include "ares.h"
#include "ares_dns.h"
#include "ares_getopt.h"
#include "ares_nowarn.h"


struct ares_socket_functions mcast_socket_io;

static ares_socket_t open_mcast_socket(int af, int type, int protocol, void * sock_func_cb_data)
{
  // TODO: create UDP socket 
  // TODO: set socket options
  // TODO: join multicast group
  fprintf(stdout, "Enter %s:%s\n", __FILE__, __func__);
  return socket(af, type, protocol);
}


static int connect_mcast_socket(ares_socket_t sockfd, const struct sockaddr * addr, socklen_t addrlen, void * sock_func_cb_data)
{
  // TODO: may not be required for UDP
  fprintf(stdout, "Enter %s:%s\n", __FILE__, __func__);
  return connect(sockfd, addr, addrlen);
}


static int close_mcast_socket(ares_socket_t sockfd, void * sock_func_cb_data)
{
  // leave multicast group
  fprintf(stdout, "Enter %s:%s\n", __FILE__, __func__);
  return close(sockfd);
}


static ssize_t recvfrom_mcast_socket(ares_socket_t sockfd, void * data, size_t data_len,
                              int flags, struct sockaddr * from, socklen_t * from_len, 
                              void * sock_func_cb_data)
{
  fprintf(stdout, "Enter %s:%s\n", __FILE__, __func__);
  return recvfrom(sockfd, data, data_len, flags, from, from_len);
}


static ssize_t sendto_mcast_socket(ares_socket_t sockfd, const struct iovec * vec, 
                            int len, void * sock_func_cb_data)
{
  fprintf(stdout, "Enter %s:%s\n", __FILE__, __func__);
  return writev(sockfd, vec, len);
}

struct ares_socket_functions * get_mcast_io_funcs()
{
  mcast_socket_io.asocket = open_mcast_socket;
  mcast_socket_io.aclose = close_mcast_socket;
  mcast_socket_io.aconnect = connect_mcast_socket;
  mcast_socket_io.arecvfrom = recvfrom_mcast_socket;
  mcast_socket_io.asendv = sendto_mcast_socket;

  return &mcast_socket_io;
}
