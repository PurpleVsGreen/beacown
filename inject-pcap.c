/*
 * cc -o inject-pcap inject-pcap.c $(pkg-config --cflags --libs  libnl-3.0 libnl-genl-3.0 libpcap)
 */

#include <netlink/netlink.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>
#include <net/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <pcap/pcap.h>

#define HWSIM_CMD_REGISTER 1
#define HWSIM_CMD_FRAME 2

#define HWSIM_ATTR_ADDR_RECEIVER 1
#define HWSIM_ATTR_FRAME 3
#define HWSIM_ATTR_RX_RATE 5
#define HWSIM_ATTR_SIGNAL 6

#define CHECK(call) do { if (call) { fprintf(stderr, "pcap failure: %s\n", errbuf); return 2; } } while (0)

static int family;

static void handle_pkt(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes)
{
	struct nl_msg *msg = nlmsg_alloc_simple(10, 0);
	struct nl_sock *sk = (void *)user;
	int err;

	genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, family,
		    0, 0, HWSIM_CMD_FRAME, 1);

	nla_put(msg, HWSIM_ATTR_ADDR_RECEIVER, 6, "\x42\x00\x00\x00\x00\x00"); 
	nla_put_u32(msg, HWSIM_ATTR_RX_RATE, 0);
	nla_put_u32(msg, HWSIM_ATTR_SIGNAL, -60);
	nla_put(msg, HWSIM_ATTR_FRAME, h->caplen, bytes);

	err = nl_send_auto(sk, msg);
	if (err < 0)
		printf("Can't send msg1: %s\n", nl_geterror(err));
	nlmsg_free(msg);
}

int main(int argc, char **argv)
{
	char errbuf[PCAP_ERRBUF_SIZE];
	int sockfd;
	struct ifreq ifr;
	int err, idx;

	if (argc < 2) {
		fprintf(stderr, "usage: %s <pcap files>\n", argv[0]);
		return 2;
	}

	CHECK(pcap_init(PCAP_CHAR_ENC_UTF_8, errbuf));

	sockfd = socket(AF_INET, SOCK_DGRAM, 0);

	if (sockfd < 0) {
		printf("Can't open socket to reset adapters");
		exit(1);
	}

	struct nl_sock *sk = nl_socket_alloc();
	if (!sk) {
		printf("Failed to allocate socket");
		exit(1);
	}

	if (genl_connect(sk) < 0) {
		printf("Failed to connect socket");
		exit(1);
	}

	family = genl_ctrl_resolve(sk, "MAC80211_HWSIM");

	err = genl_send_simple(sk, family, HWSIM_CMD_REGISTER, 1, 0);
	if (err < 0) {
		printf("Error while registering: %s\n", nl_geterror(err));
		exit(1);
	}

	memset(&ifr, 0, sizeof ifr);
	strncpy(ifr.ifr_name, "wlan0", IFNAMSIZ);
	ifr.ifr_flags |= IFF_UP;
	ioctl(sockfd, SIOCSIFFLAGS, &ifr);

	memset(&ifr, 0, sizeof ifr);
	strncpy(ifr.ifr_name, "hwsim0", IFNAMSIZ);
	ifr.ifr_flags |= IFF_UP;
	ioctl(sockfd, SIOCSIFFLAGS, &ifr);

	for (idx = 1; idx < argc; idx++) {
		pcap_t *input;

		input = pcap_open_offline(argv[idx], errbuf);
		CHECK(!input);

		pcap_loop(input, -1, handle_pkt, (void *)sk);
	}
}
