#include <pcap/pcap.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <string.h>
#include <stdlib.h>

/* Maximum time to wait for a packet to arrive */
#define TIMEOUT_MS (30000)

int main(int argc, char *argv[]) {

	char pcap_buff[PCAP_ERRBUF_SIZE];       /* Error buffer used by pcap functions */
	pcap_t *pcap_handle = NULL;             /* Handle for PCAP library */
	struct pcap_pkthdr *packet_hdr = NULL;  /* Packet header from PCAP */
	const u_char *packet_data = NULL;       /* Packet data from PCAP */
	int ret = 0;                            /* Return value from library calls */
	char *trace_file = NULL;                /* Trace file to process */
	char *dev_name = NULL;                  /* Device name for live capture */
	char use_file = 0;                      /* Flag to use file or live capture */
    struct ether_header *ethernet; /* ethernet header */
	struct ip *iphdr;   /*  ipv4 header */
	struct ip6_hdr *ip6; /* ipv6 header */
	struct tcphdr *tcp; /*  tcp header */
	struct udphdr *udp; /* udp header */

	
	/* Check command line arguments */
	if( argc > 2 ) {
		fprintf(stderr, "Usage: %s [trace_file]\n", argv[0]);
		return -1;
	}
	else if( argc > 1 ){
		use_file = 1;
		trace_file = argv[1];
	}
	else {
		use_file = 0;
	}

	/* Open the trace file, if appropriate */
	if( use_file ){
		pcap_handle = pcap_open_offline(trace_file, pcap_buff);
		if( pcap_handle == NULL ){
			fprintf(stderr, "Error opening trace file \"%s\": %s\n", trace_file, pcap_buff);
			return -1;
		}
		printf("Processing file '%s'\n", trace_file);
	}
	/* Lookup and open the default device if trace file not used */
	else{
		dev_name = pcap_lookupdev(pcap_buff);
		if( dev_name == NULL ){
			fprintf(stderr, "Error finding default capture device: %s\n", pcap_buff);
			return -1;
		}
		pcap_handle = pcap_open_live(dev_name, BUFSIZ, 1, TIMEOUT_MS, pcap_buff);
		if( pcap_handle == NULL ){
			fprintf(stderr, "Error opening capture device %s: %s\n", dev_name, pcap_buff);
			return -1;
		}
		printf("Capturing on interface '%s'\n", dev_name);
	}

	/* Loop through all the packets in the trace file.
	 * ret will equal -2 when the trace file ends.
	 * This is an infinite loop for live captures. */
	ret = pcap_next_ex(pcap_handle, &packet_hdr, &packet_data);
	while( ret != -2 ) {

		/* An error occurred */
		if( ret == -1 ) {
			pcap_perror(pcap_handle, "Error processing packet:");
			pcap_close(pcap_handle);
			return -1;
		}

		/* Timeout occured for a live packet capture */
		else if( (ret == 0) && (use_file == 0) ){
			printf("Timeout waiting for additional packets on interface '%s'\n", dev_name);
			pcap_close(pcap_handle);
			return 0;
		}

		/* Unexpected return values; other values shouldn't happen when reading trace files */
		else if( ret != 1 ) {
			fprintf(stderr, "Unexpected return value (%i) from pcap_next_ex()\n", ret);
			pcap_close(pcap_handle);
			return -1;
		}

		/* Process the packet and print results */
		else {
		    u_char *ptr; /*printing out ethernet header info*/
		    
		    /******************Process Ethernet data*******************************/
			ethernet = (struct ether_header *) packet_data;
			ptr = ethernet->ether_shost;
            int i = ETHER_ADDR_LEN;
            
            do{
                printf("%s%x",(i == ETHER_ADDR_LEN) ? " " : ":",*ptr++);
            }while(--i>0);
            printf(" -> ");

            ptr = ethernet->ether_dhost;
            i = ETHER_ADDR_LEN;
            do{
                printf("%s%x",(i == ETHER_ADDR_LEN) ? " " : ":",*ptr++);
            }while(--i>0);
            printf("\n");
            
            /********************Process IP data***********************************/
            u_int length = packet_hdr->len; /* length of packet including headers */
            u_int hlen, version;
            u_int len;

            /* jump past the ethernet header */
            iphdr = (struct ip*)(packet_data + sizeof(struct ether_header));
            length -= sizeof(struct ether_header); 

            /* check to see we have a packet of valid length */
            if (length < sizeof(struct ip))
            {
                printf("truncated ip %d",length);
                break;
            }

            len     = ntohs(iphdr->ip_len); /* Total length (header + payload) */
            hlen    = iphdr->ip_hl * 4; /* header length */
            version = iphdr->ip_v;/* ip version */

            /* IPv6 Packet */
            if(version == 6)
            {
                char *source, *destination; /* IP addresses */
				u_char ipSkipExt; /* Next header variable */
				struct ip6_ext *ipExt; /* Last extended header */
				int numOfExt = 0; /* Count headers between IP and TCP/UDP */
				int size6 = 0; /* Size of extended headers */
				
				ip6 = (struct ip6_hdr*)(packet_data + sizeof(struct ether_header) + hlen);
				ipSkipExt = ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt;
				
				source = (char *)malloc(INET6_ADDRSTRLEN);
				destination = (char *)malloc(INET6_ADDRSTRLEN);
				
				inet_ntop(AF_INET6, &ip6->ip6_src, source,
					  INET6_ADDRSTRLEN);
				inet_ntop(AF_INET6, &ip6->ip6_dst, destination,
					  INET6_ADDRSTRLEN);
				printf("\t[IPv6] %s -> %s\n", source, destination);
				
				
				ipExt = (struct ip6_ext*)(packet_data + sizeof(struct ether_header) + sizeof(struct ip6_hdr));
				
				/* Count extended headers */
				while(1)
				{
					/* If tcp/udp, no more extended headers */
					if(ipSkipExt == IPPROTO_TCP || ipSkipExt == IPPROTO_UDP)
						break;
						
					numOfExt++;
					size6 = (sizeof(struct ip6_ext) * numOfExt);
					ipExt = (struct ip6_ext*)(packet_data + sizeof(struct ether_header) + sizeof(struct ip6_hdr) + size6);
					ipSkipExt = ipExt->ip6e_nxt;
				}
				
			/******************** TCP *************************/
				if(ipSkipExt == IPPROTO_TCP)
				{
					 tcp = (struct tcphdr*)(ipExt);
		            if(length < sizeof(struct tcphdr))
		                break;
		            printf("\t[TCP] %d -> %d\n", ntohs(tcp->th_sport), ntohs(tcp->th_dport));
				}
			/******************** UDP *************************/
				else if(ipSkipExt == IPPROTO_UDP)
				{
					udp = (struct udphdr*)(ipExt);
	            	if ( length < sizeof(struct udphdr))
						break;	
				#ifdef __FAVOR_BSD
					printf("\t[UDP] %d -> %d\n", ntohs(udp->uh_sport), ntohs(udp->uh_dport));
				#else
					printf("\t[UDP] %d -> %d\n", ntohs(udp->source), ntohs(udp->dest));
				#endif
	            }
            /******************** Other Protocol *************************/
				else
				{
					printf("\t[%x]\n", ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt);
				}
				
            }
            /* IPv4 Packet */
            else if(version == 4)
            {
                /* see if we have as much packet as we should */
                if(length < len)
                    printf("\ntruncated IP - %d bytes missing\n",len - length);

                /* Print Source and Destination */
                fprintf(stdout,"\t[IPv4] ");
                fprintf(stdout,"%s -> ",
                        inet_ntoa(iphdr->ip_src));
                fprintf(stdout,"%s\n",
                        inet_ntoa(iphdr->ip_dst));
                        
                length -= hlen;
                
               /************** TCP *****************/
                if(iphdr->ip_p == IPPROTO_TCP)
                {
		            tcp = (struct tcphdr*)(packet_data + sizeof(struct ether_header) + hlen);
		            if(length < sizeof(struct tcphdr))
		                break;
		            /* print tcp ports */
		            printf("\t[TCP] %d -> %d\n", ntohs(tcp->th_sport), ntohs(tcp->th_dport));
		            
	            }
	            /************** UDP *****************/
	            else if(iphdr->ip_p == IPPROTO_UDP)
	            {
	            	udp = (struct udphdr*)(packet_data + sizeof(struct ether_header) + hlen);
	            	if ( length < sizeof(struct udphdr))
						break;	
				#ifdef __FAVOR_BSD
					printf("\t[UDP] %d -> %d\n", ntohs(udp->uh_sport), ntohs(udp->uh_dport));
				#else
					printf("\t[UDP] %d -> %d\n", ntohs(udp->source), ntohs(udp->dest));
				#endif
	            }
	            /************** Other Protocol *****************/
	            else
	            	printf("\t[%x]\n", iphdr->ip_p);
            }
            /* Not IPv4 or IPv6 */
            else
            	printf("[%d]\n", version);
			 
		}

		/* Get the next packet */
		ret = pcap_next_ex(pcap_handle, &packet_hdr, &packet_data);
	}

	/* Close the trace file or device */
	pcap_close(pcap_handle);
	return 0;
}
