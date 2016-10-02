#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <signal.h>
#include <string.h>
#include <strings.h>
#include <pcap.h>
#include <time.h>
#include <sys/times.h>
#include "hashmap.h"
#include "sniff.h"

#define CAPTURE_DEVICE  "eth0"
#define TIMEOUT         1000  /* [ms] */
#define MAX_HOSTS       32
#define FILTER_LEN      128
#define OK              0
#define ERROR           1

typedef struct Host {
    char ip[16];
    char name[64];
    int recv_bytes;
    struct Host *next;
} Host;

/* global variables */
Host g_hosts[MAX_HOSTS];
map_t g_hosts_map;
char g_filter[FILTER_LEN];
struct timeval g_tv_start, g_tv_end;


void print_stats(Host *host, double delta_sec) {
    while (host) {
        double data_rate = (double)host->recv_bytes / delta_sec;
        printf("%s,\t%s,\t%d,\t%.3f\n", host->ip, host->name, host->recv_bytes, data_rate);
        host = host->next;
    }
}


void sigcatch(int sig)
{
    gettimeofday(&g_tv_end, NULL);
    double delta_sec = 
        (double)(g_tv_end.tv_sec - g_tv_start.tv_sec) + 
        (double)(g_tv_end.tv_usec - g_tv_start.tv_usec) * 1e-6;

    fprintf(stderr, "Catched Ctrl-C signal, elapsed time = %.3f sec, stats:\n\n", delta_sec);
    print_stats(g_hosts, delta_sec);

    hashmap_free(g_hosts_map);
    exit(EXIT_SUCCESS);
}


#if 0
void packet_header_test(u_char *args,
                         const struct pcap_pkthdr *header,
                         const u_char *packet) {
    printf("Packet capture length: %d\n", header->caplen);
    printf("Packet total length %d\n", header->len);
}
#endif


void packet_handler(u_char *args,
                    const struct pcap_pkthdr *header,
                    const u_char *packet) {
    /* Below code is taken from got_packet() in sniffex.c */
	const struct sniff_ethernet *ethernet;  /* The ethernet header [1] */
	const struct sniff_ip *ip;              /* The IP header */
	const struct sniff_tcp *tcp;            /* The TCP header */
	const char *payload;                    /* Packet payload */

	int size_ip;
	int size_tcp;
	int size_payload;    

    Host *host = NULL;
    char *src_ip = NULL;
    int packet_len = 0;

	/* define ethernet header */
	ethernet = (struct sniff_ethernet*)(packet);
	
	/* define/compute ip header offset */
	ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
	size_ip = IP_HL(ip)*4;
	if (size_ip < 20) {
		fprintf(stderr, "   * Invalid IP header length: %u bytes\n", size_ip);
		return;
	}

    src_ip = inet_ntoa(ip->ip_src);
    packet_len = header->len;
    if (hashmap_get(g_hosts_map, src_ip, (void**)&host) == MAP_OK) {
        host->recv_bytes += packet_len;
        /* printf("From: %s, %d bytes, total %d bytes\n", src_ip, packet_len, host->recv_bytes); */
    }

    return;
}


void print_hosts(Host *host) {
    while (host) {
        printf("%s\t%s\n", host->ip, host->name);
        host = host->next;
    }
}


int init_hosts(char *hosts_file, Host hosts[]) {
    FILE *fp;
    char buffer[128];
    int status = OK;

    if ((fp = fopen(hosts_file, "r")) == NULL) {
        fprintf(stderr, "init_hosts: Could not open hosts file %s\n", hosts_file);
        return ERROR;
    }

    /* hosts file format: "xxx.xxx.xxx.xxx'\t'hostname'\n'" (as in /etc/hosts) */
    int i = 0;
    Host *host = NULL, *prev = NULL;
    while (fgets(buffer, 128, fp) != NULL) {
        if (MAX_HOSTS <= i) {
            fprintf(stderr, "init_hosts: Exceeded max hosts %d", i);
            status = ERROR;
            goto EXIT;
        }

        host = &hosts[i];

        char *delim = index(buffer, '\t');
        if (delim == NULL) {
            fprintf(stderr, "init_hosts: Could not find a delimiter from %s", buffer);
            status = ERROR;
            goto EXIT;
        }
        int iplen = delim - buffer;
        strncpy(host->ip, buffer, delim - buffer);
        host->ip[delim - buffer] = '\0';

        char *newline = index(buffer, '\n');
        if (delim == NULL) {
            fprintf(stderr, "init_hosts: Could not find a newline from %s", buffer);
            status = ERROR;
            goto EXIT;
        }
        int namelen = newline - delim - 1;
        strncpy(host->name, delim + 1, namelen);
        host->name[namelen] = '\0';

        host->recv_bytes = 0;
        
        if (prev) prev->next = host;
        prev = host;
        i++;
    }

EXIT:
    fclose(fp);

    return status;
}


int create_hosts_map(Host *hosts, map_t *map) {
    Host *host = hosts;
    int status = OK;

    *map = hashmap_new();
    while (host) {
        if (hashmap_put(*map, host->ip, host) != MAP_OK) {
            status = ERROR;
            break;
        }
        host = host->next;
    }

    return status;
}


int create_filter(Host *host, char *filter) {
    int len = 0;
    int status = OK;

    strcat(filter, "src ");
    len += 4;

    while (host) {
        if (FILTER_LEN <= len + strlen(host->ip)) {
            status = ERROR;
            break;
        }
        strcat(filter, host->ip);

        if (host->next) {
            if (FILTER_LEN <= len + 4) {
                status = ERROR;
                break;
            }
            strcat(filter, " or ");
        }

        host = host->next;
    }

    if (FILTER_LEN <= len + 1)
        status = ERROR;
    else
        strcat(filter, "\0");

    if (status == ERROR)
        fprintf(stderr, "create_filter: Exceeded max filter length");

    return status;
}


int main(int argc, char *argv[]) {
    char error_buffer[PCAP_ERRBUF_SIZE], *hosts_file;
    pcap_t *handle;
    char *dev = CAPTURE_DEVICE;
	struct bpf_program compiled_filter;

    if (argc < 2) {
        fprintf(stderr, "Usage: ./ipmon [hosts file]");
        exit(EXIT_FAILURE);
    }
    hosts_file = argv[1];

    /* setup a Ctrl-C signal handler */
    if (SIG_ERR == signal(SIGINT, sigcatch) ) {
        fprintf(stderr, "Failed to set signal handler\n");
        exit(EXIT_FAILURE);
    }

    if (init_hosts(hosts_file, g_hosts) != 0) {
        fprintf(stderr, "Fail to initialize hosts from file %s\n", hosts_file);
        exit(EXIT_FAILURE);
    }
    printf("Started monitoring traffic from the following hosts:\n\n");
    print_hosts(g_hosts);
    if (create_hosts_map(g_hosts, &g_hosts_map) != 0) {
        fprintf(stderr, "Failed to create hash map\n");
        exit(EXIT_FAILURE);
    }
    printf("\n");

    /* open device for live capture */
    handle = pcap_open_live(dev, BUFSIZ, 0 /* no promisc */, TIMEOUT, error_buffer);
    if (handle == NULL) {
         fprintf(stderr, "Could not open device %s: %s\n", dev, error_buffer);
        exit(EXIT_FAILURE);
    }

    /* create a filter from the hosts file: connecting src hosts with OR conditions */
    if (create_filter(g_hosts, g_filter) != 0) {
        fprintf(stderr, "Failed to create filter\n");
        exit(EXIT_FAILURE);
    }
	if (pcap_compile(handle, &compiled_filter, g_filter, 0, 0) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n", g_filter, pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}

	/* apply the compiled filter */
	if (pcap_setfilter(handle, &compiled_filter) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n", g_filter, pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}

    gettimeofday(&g_tv_start, NULL);

    pcap_loop(handle, 0, packet_handler, NULL);

EXIT:
    /* never gets here */
    return EXIT_SUCCESS;

}
