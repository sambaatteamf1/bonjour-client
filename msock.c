
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
#include <netinet/ip.h> /* superset of previous */


#define MDNS_MCAST_ADDR "224.0.0.251"
struct ares_socket_functions mcast_socket_io;

static ares_socket_t open_mcast_socket(int af, int type, int protocol, void * sock_func_cb_data)
{
  struct ip_mreqn mreq;
  struct sockaddr_in sa;
  int sockfd = -1;
  int flags = 0;
  in_addr_t addr;

  sockfd = socket(AF_INET, SOCK_DGRAM, 0);
  if (sockfd < 0 )
    {
    fprintf(stderr, "socket() failed: %s\n", strerror(errno));      
    goto open_socket_failed;
    }

  flags = 1;  
  if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &flags, sizeof(flags)) < 0) 
    {
      fprintf(stderr, "setsockopt() - SO_REUSEADDR failed: %s\n", strerror(errno));
      goto open_socket_failed;
    }

  memset(&sa, 0, sizeof(sa));
  sa.sin_family = AF_INET;
  sa.sin_port= htons(5353);
  addr = inet_addr(MDNS_MCAST_ADDR);
  sa.sin_addr = *(struct in_addr *)&addr;

  if (bind(sockfd, (struct sockaddr*) &sa, sizeof(sa)) < 0) 
    {
      fprintf(stderr, "bind() failed: %s\n", strerror(errno));
      goto open_socket_failed;
    }

  memset(&mreq, 0, sizeof(mreq));
  mreq.imr_multiaddr = sa.sin_addr;

  addr = htonl(INADDR_ANY);
  mreq.imr_address = *(struct in_addr *)&addr;
  mreq.imr_ifindex = 0;

  if (setsockopt(sockfd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0) 
    {
      fprintf(stderr, "IP_ADD_MEMBERSHIP failed: %s\n", strerror(errno));
      goto open_socket_failed;
    }

  flags = 1;
  if (setsockopt(sockfd, IPPROTO_IP, IP_MULTICAST_TTL, &flags, sizeof(flags)) < 0)
    {
      fprintf(stderr, "setsockopt - IP_MULTICAST_TTL failed: %s\n", strerror(errno));
      goto open_socket_failed;      
    }

  if (fcntl(sockfd, F_SETFD, FD_CLOEXEC) < 0)
    {
      fprintf(stderr, "FD_CLOEXEC failed: %s\n", strerror(errno));
      goto open_socket_failed;
    }

  flags = 0;
  if ((flags = fcntl(sockfd, F_GETFL)) < 0)
    {
      fprintf(stderr, "F_GETFL failed: %s\n", strerror(errno));
      goto open_socket_failed;       
    }

  if (fcntl(sockfd, F_SETFL, flags|O_NONBLOCK) < 0)
    {
      fprintf(stderr, "F_SETFL failed: %s\n", strerror(errno));
      goto open_socket_failed;       
    }

   return sockfd;

  open_socket_failed:
    if (sockfd > 0) 
      close(sockfd);

    return -1;
}

static int connect_mcast_socket(ares_socket_t sockfd, const struct sockaddr * addr, socklen_t addrlen, void * sock_func_cb_data)
{
  return 0;  
}


static int close_mcast_socket(ares_socket_t sockfd, void * sock_func_cb_data)
{
  if (sockfd < 0)
    return -1;

  return close(sockfd);
}


static ssize_t recvfrom_mcast_socket(ares_socket_t sockfd, void * data, size_t data_len,
                              int flags, struct sockaddr * from, socklen_t * from_len, 
                              void * sock_func_cb_data)
{
  return recvfrom(sockfd, data, data_len, flags, from, from_len);
}


static ssize_t sendto_mcast_socket(ares_socket_t sockfd, const struct iovec * vec, 
                            int len, void * sock_func_cb_data)
{
  struct sockaddr_in sa;
  struct msghdr msg;
  struct cmsghdr *cmsg;
  struct in_pktinfo *pkti;
  uint8_t cmsg_data[sizeof(struct cmsghdr) + sizeof(struct in_pktinfo)];  
  ssize_t ret;
  in_addr_t addr;
  struct ifreq ifreq[32];  
  struct ifconf ifconf;
  int index = 0;
  int numIfs = 0;

  memset(cmsg_data, 0, sizeof(cmsg_data));
  cmsg = (struct cmsghdr*) cmsg_data;
  cmsg->cmsg_len = sizeof(cmsg_data);
  cmsg->cmsg_level = IPPROTO_IP;
  cmsg->cmsg_type = IP_PKTINFO;

  memset(&sa, 0, sizeof(sa));
  sa.sin_family = AF_INET;
  sa.sin_port= htons(5353);
  addr = inet_addr(MDNS_MCAST_ADDR);
  sa.sin_addr = *(struct in_addr *)&addr;  
 
  ifconf.ifc_req = ifreq;
  ifconf.ifc_len = sizeof(ifreq);
    
  if (ioctl(sockfd, SIOCGIFCONF, &ifconf) < 0) 
  {
    fprintf(stderr, "SIOCGIFCONF failed: %s\n", strerror(errno));
    return -1;
  }

  numIfs = ifconf.ifc_len/sizeof(struct ifreq);

  for (index = 0; index < numIfs; index++) 
  {
    struct ifreq * ifr;

    ifr = &ifconf.ifc_req[index];
    
    if (ioctl(sockfd, SIOCGIFFLAGS, ifr) < 0) 
      continue; 

    if (!(ifr->ifr_flags & IFF_MULTICAST) ||
        !(ifr->ifr_flags & IFF_UP) ||
        !(ifr->ifr_flags & IFF_RUNNING))
      continue;

    pkti = (struct in_pktinfo*) (cmsg_data + sizeof(struct cmsghdr));
    pkti->ipi_ifindex = if_nametoindex(ifr->ifr_name);

    memset(&msg, 0, sizeof(msg));
    msg.msg_name = &sa;
    msg.msg_namelen = sizeof(sa);
    msg.msg_iov = (struct iovec *)vec;
    msg.msg_iovlen = len;
    msg.msg_control = cmsg_data;
    msg.msg_controllen = sizeof(cmsg_data);
    msg.msg_flags = 0;

    if ((ret = sendmsg(sockfd, &msg, MSG_DONTROUTE)) < 0)
      {
        fprintf(stderr, "sendmsg() failed: %s\n", strerror(errno));
        return -1;
      }
    
  }

  return ret;    
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
