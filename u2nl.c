/*
 *  u2nl - universal tunnel
 *  Author: Christian Reitwiessner <christian@reitwiessner.de>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <netdb.h>
#include <sys/select.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/netfilter_ipv4.h>

#define BUF_SIZE 2048
static char *packet_buffer = NULL;

static struct sockaddr_in proxy_addr;


static int forward(int from, int to)
{
	int len = read(from, packet_buffer, BUF_SIZE);
	if (len == 0) {
		return -1;
	} else if (len < 0) {
		perror("read");
		return -1;
	}

	if (write(to, packet_buffer, len) != len) {
		perror("write");
		return -1;
	}

	return 0;
}

static void forwardLoop(int csock, int ssock)
{
	fd_set fds;
	int maxfd = csock > ssock ? csock + 1 : ssock + 1;
	
	packet_buffer = malloc(BUF_SIZE);
	if (packet_buffer == NULL) {
		perror("Out of memory");
		return;
	}

	FD_ZERO(&fds);
	FD_SET(csock, &fds);
	FD_SET(ssock, &fds);
	while (1) {
		int err;
		fd_set selfds;

		memcpy(&selfds, &fds, sizeof(fds));

		err = select(maxfd, &selfds, NULL, NULL, NULL);
		if (err <= 0) {
			perror("select");
			return;
		}

		if (FD_ISSET(csock, &selfds)) {
			if (forward(csock, ssock) != 0) {
				exit(0);
			}
		}
		if (FD_ISSET(ssock, &selfds)) {
			if (forward(ssock, csock) != 0) {
				exit(0);
			}
		}
	}
}

static int connectHttps(int s, struct sockaddr_in *addr, int c)
{
	char buf[512];
	char *headerend = NULL;
	int header_length;
	int len = snprintf(buf, 512, "CONNECT %s:%d HTTP/1.0\r\n\r\n",
			inet_ntoa(addr->sin_addr),
			ntohs(addr->sin_port));
	if (write(s, buf, len) != len) {
		perror("Error writing to proxy");
		return -1;
	}

	while (headerend == NULL) {
		len = read(s, buf, 512);
		if (len <= 0) {
			perror("Error reading from proxy");
			return -1;
		}
		
		headerend = strstr(buf, "\r\n\r\n");
	}

	header_length = headerend + 4 - buf; 
	if (header_length < len) {
		if (write(c, headerend + 4,
					len - header_length) != (len - header_length)) {
			perror("Error writing to client");
			return -1;
		}
	}
	return 0;
}

static int createServerSocket(char *host, int port)
{
	int sock;
	struct hostent *he;
	struct sockaddr_in addr;
	int one = 1;

	he = gethostbyname(host);
	if (he == 0)
		return -1;

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	memcpy(&addr.sin_addr.s_addr, he->h_addr_list[0], he->h_length);

	sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock < 0)
		return -1;

	if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR,
				(char *) &one, sizeof(one)) < 0) {
		close(sock);
		return -1;
	}

	if (bind(sock, (struct sockaddr *) &addr, sizeof(addr)) != 0) {
		close(sock);
		return -1;
	}

	if (listen(sock, 4) != 0) {
		close(sock);
		return -1;
	}

	return sock;
}

static int getOrigDst(int fd, struct sockaddr_in *dst)
{
	size_t sock_sz = sizeof(*dst);
	memset(dst, 0, sizeof(*dst));

	return getsockopt(fd, SOL_IP, SO_ORIGINAL_DST, dst, &sock_sz);
}

static void newConnection(int csock)
{
	struct sockaddr_in dst;
	int ssock;

	if (getOrigDst(csock, &dst) != 0) {
		perror("Unable to get original destination of connection");
		close(csock);
		return;
	}

	printf("Handling connection to %s.\n",
			inet_ntoa(dst.sin_addr));

	ssock = socket(AF_INET, SOCK_STREAM, 0);
	if (ssock < 0) {
		perror("Unable to create new server socket");
		close(csock);
		return;
	}

	if (connect(ssock, (struct sockaddr *) &proxy_addr,
				sizeof(proxy_addr)) != 0) {
		perror("Unable to connect to proxy");
		close(csock);
		close(ssock);
		return;
	}

	if (connectHttps(ssock, &dst, csock) != 0) {
		close(csock);
		close(ssock);
		return;
	}
	
	forwardLoop(csock, ssock);
}


static int acceptLoop(int fd)
{
	int err;
	while (1) {
		struct sockaddr_in addr;
		socklen_t addrlen = sizeof(addr);
		int csock;

		csock = accept(fd, (struct sockaddr *) &addr, &addrlen);
		if (csock < 0) {
			perror("Error accepting connection");
			return -1;
		}
			
		switch (fork()) {
			case -1:
				perror("Unable to fork");
				return -1;
			case 0:
				switch (fork()) {
					case -1:
						perror("Unable to fork");
						return -1;
					case 0:   /* grandchild */
						close(fd);
						newConnection(csock);
						exit(1);
					default:  /* child */
						exit(0);
				}
			default:		/* parent */
				wait();
				close(csock);
				break;
		}
	}

	return err;
}

static int createProxyAddr(char *host, int port)
{
	struct hostent *he;

	he = gethostbyname(host);
	if (he == 0)
		return -1;

	memset(&proxy_addr, 0, sizeof(proxy_addr));
	proxy_addr.sin_family = AF_INET;
	proxy_addr.sin_port = htons(port);
	memcpy(&proxy_addr.sin_addr.s_addr, he->h_addr_list[0], he->h_length);

	return 0;
}


int main(int argc, char *argv[])
{
	int err;
	int fd;

	char *listen_addr;
	int listen_port;
	
	if (argc == 4) {
		listen_addr = "0.0.0.0";
		listen_port = atoi(argv[3]);
	} else if (argc == 5) {
		listen_addr = argv[3];
		listen_port = atoi(argv[4]);
	} else {
		printf("Usage: %s <proxy host> <proxy port> "
				"[<listen address>] <listen port>\n"
				"Tunnels all TCP connections redirected "
				"by the local linux iptables firewall\n"
				"to <listen port> via the http proxy "
				"<proxy host>, which has to support the\n"
				"HTTPS/SSL CONNECT command.\n"
				"Use\n# iptables -t nat -A OUTPUT -p tcp "
				"-d ! <proxy host> \\\n"
				"\t-j REDIRECT --to-port <listen port>\n"
				"or a similar command to configure "
				"the firewall.\n",
				argv[0]);
		exit(1);
	}

	fd = createServerSocket(listen_addr, listen_port);

	if (fd < 0) {
		perror("Error opening server socket");
		return fd;
	}

	if (createProxyAddr(argv[1], atoi(argv[2])) != 0) {
		perror("Error resolving proxy address");
		close(fd);
		return -1;
	}

	err = acceptLoop(fd);

	if (err < 0) {
		perror("Error in accept loop");
		close(fd);
		return err;
	}

	close(fd);
	return 0;
}
