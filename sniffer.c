/*
 *******************************************************************************
 * NWEN302 Project 1 : Ethernet packet sniffer
 * Name: Corey Wilkinson
 * ID: 300342936
 * ECS username: wilkincore
 *******************************************************************************
 * David C Harrison (david.harrison@ecs.vuw.ac.nz) supplied base code (20 lines)
 * Refer to first commit on my repo: https://github.com/CoreyNZ/packet_sniffer
 *
 * Using libcap in C: http://www.devdungeon.com/content/using-libpcap-c
 * was a particularly helpful resource for determing the packet types.
 * No code was copied, but the resource prompted hints on how to
 * approach certain problems & errors I was encountering.
 *******************************************************************************
 * To compile: gcc -o sniffer sniffer.c -l pcap
 * To run: tcpdump -s0 -w - | ./sniffer -
 *     Or: ./sniffer <some file captured from tcpdump or wireshark>
 *******************************************************************************
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

/* Required Libaries */
#include <stdio.h>
#include <pcap.h>
#include <stdbool.h>
#include <arpa/inet.h>

/* Libraries for header declarations */
#include <netinet/ether.h>              //ethernet header
#include <netinet/tcp.h>                //tcp header
#include <netinet/udp.h>                //udp header
#include <netinet/ip_icmp.h>            //icmp header
#include <netinet/icmp6.h>              //icmpv6 header
#include <netinet/ip.h>                 //ipv4 protocols
#include <netinet/ip6.h>                //ipv6 protocols

/* Prototypes */
void got_packet(u_char *, const struct pcap_pkthdr *, const u_char *);
void got_ipv6(int, int, const u_char*, char*);
void print_udp (const u_char*, int*);
void print_tcp (const u_char*, int*);
void print_ipv4(char*, char*);
void print_icmp6(const u_char*, int*);
void print_ipv6();
void printData(const u_char *, int);

/* Global Variables */
int counter = 0;
int headerLength = 0;

/* Declaring IPV4 & IPV6 destination addresses */
char srcIPV4[INET_ADDRSTRLEN];
char destIPV4[INET_ADDRSTRLEN];

char srcIPV6[INET_ADDRSTRLEN];
char destIPV6[INET_ADDRSTRLEN];

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
  /* Declaring pointers to packet headers */
  const struct ether_header *ethernet_header;
  const struct ip *ipv4_header;
  const struct ip6_hdr *ipv6_header;
  const struct tcphdr *tcp_header;
  const struct udphdr *udp_header;
  const struct icmphdr *icmp_header;

  /* Define ethernet header */
  ethernet_header = (struct ether_header*)(packet);

  /* Header length */
  headerLength = header->len;

  /* Increase packet counter */
  ++counter;

  /* Retrieve size of ethernet header */
  int size = 0;
  size += sizeof(struct ether_header);


  /* Determine the traffic type and protocol type (IPV4)*/
  switch(ntohs(ethernet_header->ether_type)){
    case ETHERTYPE_IP:
      /* Get IPV4 Header, Source, Destination address, header size */
      ipv4_header = (struct ip*)(packet + size);

      inet_ntop(AF_INET, &(ipv4_header->ip_src), srcIPV4, INET_ADDRSTRLEN);
		  inet_ntop(AF_INET, &(ipv4_header->ip_dst), destIPV4, INET_ADDRSTRLEN);

      size += sizeof(struct ip);

      /* Payload */
      u_char *payload;
		  int dataLength = 0;

        /* Determine protocol type of IPV4 header */
        switch(ipv4_header->ip_p){

          case IPPROTO_TCP:
             print_ipv4(srcIPV4, destIPV4);
   			     print_tcp(packet, &size);
   			     break;

          case IPPROTO_UDP:
 			      print_ipv4(srcIPV4, destIPV4);
 			      print_udp(packet, &size);
 			      break;

          case IPPROTO_ICMP:
  			     print_ipv4(srcIPV4, destIPV4);
  			     printf("Protocol: ICMP \n");

             icmp_header = (struct icmphdr*)(packet + sizeof(struct ether_header) + sizeof(struct ip));
             u_int type = icmp_header->type;

             /* Payload */
             payload = (u_char*)(packet + sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct icmphdr));
			       dataLength = header->len - (sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct icmphdr));
			       printf("Payload: (%d bytes) \n", dataLength);
			       printf("\n");
			       printData(payload, dataLength);

             break;

          /* Unknown Protocol */
          default:
            printf("Protocol: Unknown \n");
            break;
         }
     break;

     /* Determine the traffic type (IPV6)*/
     case ETHERTYPE_IPV6:
       /* Get IPV6 Header, Source, Destination address, header size */
       ipv6_header = (struct ip6_hdr*)(packet + size);

       inet_ntop(AF_INET6, &(ipv6_header->ip6_src), srcIPV6, INET6_ADDRSTRLEN);
		   inet_ntop(AF_INET6, &(ipv6_header->ip6_dst), destIPV6, INET6_ADDRSTRLEN);
       int nextheader = ipv6_header->ip6_nxt;

       size += sizeof(struct ip6_hdr);

       char string[100] = " ";

       got_ipv6(nextheader, size, packet, string);
       break;

      /* Anon Traffic */
    default:
      printf("Ether Type: Other \n");
      break;
    }
}

void got_ipv6(int header, int size, const u_char *packet, char *string)
{
  /* Determine the protocol type (IPV6)*/
  switch(header){

    case IPPROTO_ROUTING:
		  strcat(string, "ROUTING, ");
		  struct ip6_rthdr* header = (struct ip6_rthdr*)(packet + size);
		  size+=sizeof(struct ip6_rthdr);
		  print_ipv6(header->ip6r_nxt, size, packet, string);
		  break;

    case IPPROTO_HOPOPTS:
  		strcat(string, "HOP-BY_HOP, ");
  		struct ip6_hbh* header_hop = (struct ip6_hbh*)(packet + size);
  		size+=sizeof(struct ip6_hbh);
  		print_ipv6(header_hop->ip6h_nxt, size, packet, string);
  		break;

    case IPPROTO_FRAGMENT:
  		strcat(string, "FRAGMENTATION, ");
  		struct ip6_frag* header_frag = (struct ip6_frag*)(packet + size);
  		size+=sizeof(struct ip6_frag);
  		print_ipv6(header_frag->ip6f_nxt, size, packet, string);
  		break;

    case IPPROTO_DSTOPTS:
  		strcat(string, "Destination options, ");
  		struct ip6_dest* header_dest = (struct ip6_dest*)(packet + size);
  		size+=sizeof(struct ip6_dest);
  		print_ipv6(header_dest->ip6d_nxt, size, packet, string);
  		break;

    case IPPROTO_TCP:
  		print_ipv6();
  		printf("%s \n", string);
  		print_tcp(packet, &size);
  		break;

    case IPPROTO_UDP:
  		print_ipv6();
  		printf("%s \n", string);
  		print_udp(packet, &size);
  		break;

    case IPPROTO_ICMPV6:
  		print_ipv6();
  		printf("%s \n", string);
  		print_icmp6(packet, &size);
  		break;

    default:
  		print_ipv6();
  		printf("Protocol: Unknown \n");
  		break;
  }
}

/* Prints IPv6 header */
void print_ipv6()
{
    printf("\n");
    printf("**************************************************** \n");
    printf("Packet #: %d \n", counter);
    printf("Ether Type: IPv6 \n");
    printf("From: %s \n", srcIPV6);
    printf("To: %s \n", destIPV6);
    printf("Extension Headers:");
}

/* Prints ICMPv6 header */
void print_icmp6(const u_char *packet, int *size)
{
    printf("Protocol: ICMPv6 \n");

    u_char *payload;
    int dataLength = 0;

    /* Get icmp6 header and print out the payload */
    struct icmp6_hdr* header_icmp6 = (struct icmp6_hdr*)(packet+*size);
    payload = (u_char*)(packet + *size + sizeof(struct icmp6_hdr));
    dataLength = headerLength - *size + sizeof(struct icmp6_hdr);

    printf("Payload: (%d bytes) \n", dataLength);
    printData(payload, dataLength);
}

/* Prints TCP header */
void print_tcp(const u_char *packet, int *size)
{
    const struct tcphdr* tcp_header;
    u_int sourPort, destPort;
    u_char *payload;
    int dataLength = 0;

    /* Get TCP header, source, destination, port number and payload */
    tcp_header = (struct tcphdr*)(packet + *size);
    sourPort = ntohs(tcp_header->source);
    destPort = ntohs(tcp_header->dest);
    *size += tcp_header->doff*4;
    payload = (u_char*)(packet + *size);
    dataLength = headerLength - *size;

    /* Protocol Details */
    printf("protocol: TCP \n");
    printf("Src port: %d\n", sourPort);
    printf("Dst port: %d\n", destPort);
    printf("Payload: (%d bytes) \n", dataLength);
    printf("\n");

    printData(payload, dataLength);
}

/* Prints UDP header */
void print_udp(const u_char *packet, int *size)
{
    const struct udphdr* udp_header;

    u_int sourPort, destPort;
    u_char *payload;
    int dataLength = 0;


    /* Get UDP header, source, destination, port number and payload */
    udp_header = (struct udphdr*)(packet + *size);
    sourPort = ntohs(udp_header->source);
    destPort = ntohs(udp_header->dest);
    *size+=sizeof(struct udphdr);
    payload = (u_char*)(packet + *size);
    dataLength = headerLength - *size;

    /* Protocol details */
    printf("protocol: UDP \n");
    printf("Src port: %d\n", sourPort);
    printf("Dst port: %d\n", destPort);
    printf("Payload: (%d bytes) \n", dataLength);
    printf("\n");

    printData(payload, dataLength);
}

/* Prints IPv4 header  */
void print_ipv4(char *source, char *dest)
{
    printf("\n");
    printf("**************************************************** \n");
    printf("Packet #: %d \n", counter);
    printf("Ether Type: IPv4 \n");
    printf("From: %s \n", source);
    printf("To: %s \n", dest);
}

/*
 * Used PrintData method from http://www.binarytides.com/packet-sniffer-code-c-libpcap-linux-sockets/
 * I have made slight modifications to their printData method.
*/

void printData(const u_char *payload, int Size)
{
    int i , j;
    for(i = 0; i < Size; i++){
        if( i!=0 && i%16==0){
            printf("         ");

	    for(j = i - 16; j < i; j++){
                if(payload[j] >= 32 && payload[j] <= 128){
                    printf("%c",(unsigned char)payload[j]);
		}
                else{
		    printf(".");
		}
            }
            printf("\n");
        }

        if(i%16 == 0) printf("   ");
            printf(" %02X",(unsigned int)payload[i]);

        if(i == Size - 1){
            for(j = 0; j < 15 - i%16; j++){
		printf("   ");
            }

            printf("         ");

            for(j = i - i%16; j <= i; j++){
                if(payload[j] >= 32 && payload[j] <= 128){
		    printf("%c",(unsigned char)payload[j]);
                }
                else{
		    printf(".");
                }
            }
            printf("\n" );
        }
    }
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        printf("Did you remember to add the PCAP file in the command line?");
        fprintf(stderr, "Must have an argument, either a file name or '-'\n");
        return -1;
    }

    if(argc > 2){
	     printf("Incorrect command. \n");
       printf("Please use following format command: $./sniffer [captured_file_name] \n");
	     return -1;
    }

    pcap_t *handle = pcap_open_offline(argv[1], NULL);
    pcap_loop(handle, 1024*1024, got_packet, NULL);
    pcap_close(handle);

    return 0;
}
