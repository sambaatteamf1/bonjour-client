
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


#include <inttypes.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <assert.h>
#include <sys/time.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <net/if.h>


struct ares_socket_functions mcast_socket_io;

static ares_socket_t open_mcast_socket(int af, int type, int protocol, void * sock_func_cb_data)
{
  // TODO: create UDP socket 
  // TODO: set socket options
  // TODO: join multicast group
  fprintf(stdout, "Enter %s:%s\n", __FILE__, __func__);
  return socket(af, type, protocol);

#if 0
  struct ip_mreqn mreq;
  struct sockaddr_in sa;
  int sockfd = -1;

  sockfd = socket(AF_INET, SOCK_DGRAM, 0);
  if (sockfd < 0 )
    {
    fprintf(stderr, "socket() failed: %s\n", strerror(errno));      
    goto open_socket_failed;
    }

  flag = 1;  
  if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &flag, sizeof(flag)) < 0) 
    {
      fprintf(stderr, "setsockopt() - SO_REUSEADDR failed: %s\n", strerror(errno));
      goto open_socket_failed;
    }

  memset(&sa, 0, sizeof(sockaddr_in));
  sa.sin_family = AF_INET;
  sa.sin_port= htons(5353);
  sa.sin_addr = inet_addr("224.0.0.251");

  if (bind(fd, (struct sockaddr*) &sa, sizeof(sa)) < 0) 
    {
      fprintf(stderr, "bind() failed: %s\n", strerror(errno));
      goto open_socket_failed;
    }

  memset(&mreq, 0, sizeof(mreq));
  mreq.imr_multiaddr = sa.sin_addr;
  mreq.imr_address = htonl(INADDR_ANY);
  mreq.imr.ifindex = if_nametoindex("eth0");

  if (setsockopt(sockfd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0) 
    {
      fprintf(stderr, "IP_ADD_MEMBERSHIP failed: %s\n", strerror(errno));
      goto open_socket_failed;
    }

  ttl = 1;
  if (setsockopt(sockfd, IPPROTO_IP, IP_MULTICAST_TTL, &ttl, sizeof(ttl)) < 0)
    {
      fprintf(stderr, "setsockopt - IP_MULTICAST_TTL failed: %s\n", strerror(errno));
      goto open_socket_failed;      
    }

  if (set_cloexec(sockfd) < 0) 
    {
      fprintf(stderr, "FD_CLOEXEC failed: %s\n", strerror(errno));
      goto open_socket_failed;
    }
  
  if (set_nonblock(sockfd) < 0) 
    {
      fprintf(stderr, "O_ONONBLOCK failed: %s\n", strerror(errno));
      goto open_socket_failed;
    }

  open_socket_failed:
    if (sockfd > 0) 
      close(sockfd);

    return -1;
#endif    
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
