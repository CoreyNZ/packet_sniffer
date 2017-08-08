/*
 *******************************************************************************
 * NWEN302 Project 1 : ethernet packet sniffer (written in C)
 * Name: Corey Wilkinson
 * ID: 300342936
 * ECS username: wilkincore
 * sniffer.c
 *
 * David C Harrison (david.harrison@ecs.vuw.ac.nz) 
 * July 2015 supplied base code (20 lines)
 * Refer to the first commit on CoreyNZ github profile.
 *
 * To compile: gcc -o sniffer sniffer.c -l pcap
 *******************************************************************************
 * To run: tcpdump -s0 -w - | ./sniffer -
 *     Or: ./sniffer <some file captured from tcpdump or wireshark>
 * Current captured files, are:
 *            -> vuw.ac.nz-index.html-stream.pcap
 *            -> v6.pcap
 *            -> icmp.pcap
 *            -> udp.pcap
 *******************************************************************************
 * The sniffer.c is capable of identifying the following,
 *  -> IPV4
 *    -> UDP
 *    -> TCP
 *    -> ICMP
 *    -> Unknown
 *  -> IPV6
 *    -> IPv6 Extension Headers
 *    -> UDP
 *    -> TCP
 *    -> ICMPv6
 *    -> Unknown
 *******************************************************************************
*/

#include <stdio.h>
#include <pcap.h>

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    printf("Header Length: %d\n", header->len);
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "Must have an argument, either a file name or '-'\n");
        return -1;
    }

    pcap_t *handle = pcap_open_offline(argv[1], NULL);
    pcap_loop(handle, 1024*1024, got_packet, NULL);
    pcap_close(handle);

    return 0;
}
