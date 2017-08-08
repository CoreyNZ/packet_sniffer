/*
 *******************************************************************************
 * NWEN302 Project 1 : ethernet packet sniffer
 * Name: Corey Wilkinson
 * ID: 300342936
 * ECS username: wilkincore
 * sniffer.c
 *
 * David C Harrison (david.harrison@ecs.vuw.ac.nz) supplied base code (20 lines)
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
void print_tcp (const u_char*, int*);
void print_udp (const u_char*, int*);
void print_payload (const u_char *, int);
void print_ipv4(char*, char*);

/* Global Variables */
int packet_counter = 0;
int headerLength = 0;

char srcIPV6[INET_ADDRSTRLEN];
char destIPV6[INET_ADDRSTRLEN];

bool ipv4_bool = true;
bool ipv6_bool = true;
bool udp_bool = true;
bool tcp_bool = true;
bool icmp_bool = true;
bool other_traffic_bool = true;
bool unknown_protocol_bool = true;



void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
  /* Declaring pointers to packet headers */
  const struct ether_header *ethernet_header;
  const struct ip *ipv4_header;
  const struct ip6_hdr *ipv6_header;
  const struct tcphdr *tcp_header;
  const struct udphdr *udp_header;
  const struct icmphdr *icmp_header;

  /* Declaring IPv4 source and destination address */
  char srcIPV4[INET_ADDRSTRLEN];
  char destIPV4[INET_ADDRSTRLEN];

  /* Define ethernet header */
  ethernet_header = (struct ether_header*)(packet);

  /* Header length */
  headerLength = header->len;

  /* Increase packet counter */
  ++packet_counter

  /* Retrieve size of ethernet header */
  int size = 0;
  size += sizeof(struct ether_header);


  /* Determine the traffic type and protocol type (IPV4)*/
  switch(ntohs(ethernet_header->ether_type)){
    case ETHERTYPE_IP:
      if(ipv4_bool == false) {
        return;
      }
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
			       if(tcp_bool == false){
			            return;
			       }
             print_ipv4(srcIPV4, destIPV4);
   			     print_tcp(packet, &size);
   			     break;

          case IPPROTO_UDP:
 			      if(udp_bool == false){
 			          return;
 			      }
 			      print_ipv4(srcIPV4, destIPV4);
 			      print_udp(packet, &size);
 			      break;

          case IPPROTO_ICMP:
  			     if(icmp_bool == false){
  			          return;
  			     }
  			     print_ipv4(srcIPV4, destIPV4);
  			     printf("Protocol: ICMP \n");

             icmp_header = (struct icmphdr*)(packet + sizeof(struct ether_header) + sizeof(struct ip));
             u_int type = icmp_header->type;

             if(type == 11){
			            printf("TTL Expired! \n");
			       }
			       else if(type == ICMP_ECHOREPLY){
			            printf("ICMP Echo Reply! \n");
			       }

             /* Payload */
             payload = (u_char*)(packet + sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct icmphdr));
			       dataLength = header->len - (sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct icmphdr));
			       printf("Payload: (%d bytes) \n", dataLength);
			       printf("\n");
			       print_payload(payload, dataLength);

             break;

          /* Unknown Protocol */
          default:
            if(unknown_protocol_bool == false){
              return;
            }
            printf("Protocol: Unknown \n");
            break;
         }
     break;

     /* Determine the traffic type (IPV6)*/
     case ETHERTYPE_IPV6:
		   if(ipv6_bool == false){
		    return;
		   }

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
      if(other_traffic_bool == false){
        return;
      }

      printf("Ether Type: Other \n");
      break;
    }
}

void got_ipv6(int header, int size, const u_char *packet, char *string)
{
  /* Determine the protocol type (IPV6)*/
  
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
