#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <jansson.h>
#include <unistd.h>
#include <time.h>

#define MAX_PACKETS_PER_FILE 100
#define MAX_FILE_COUNT 10
#define FILENAME_FORMAT "packet_logs_%d.json"
#define SRC_FORMAT "/home/dtechking/Documents/Network Project Python/log_capture/%s"
#define DST_FORMAT "/home/dtechking/Documents/Network Project Python/captured_logs/%s"

int packet_count = 0;
int file_count = 1;

// Function to convert binary data to hexadecimal string
void print_hex(const unsigned char *data, int length, char *hex_string) {
    for (int i = 0; i < length; i++) {
        sprintf(hex_string + i * 2, "%02X", data[i]);
    }
}

// Function to create ASCII representation of packet data
void print_ascii(const unsigned char *data, int length, char *ascii_string) {
    for (int i = 0; i < length; i++) {
        if (isprint(data[i])) {
            ascii_string[i] = data[i];
        } else {
            ascii_string[i] = '.';
        }
    }
    ascii_string[length] = '\0';  // Null-terminate the ASCII string
}

void create_packet_json(const struct pcap_pkthdr *pkthdr, const struct ether_header *eth_header,
                        const struct ip *ip_header, const unsigned char *packet) {
    // JSON object to store packet information
    json_t *root = json_object();

    json_object_set_new(root, "PacketNumber", json_integer(++packet_count));

    // Print timestamp
    char timestamp[20];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", localtime(&pkthdr->ts.tv_sec));
    json_object_set_new(root, "Timestamp", json_string(timestamp));

    // Ethernet header
    char source_mac[18], dest_mac[18];
    snprintf(source_mac, sizeof(source_mac), "%02x:%02x:%02x:%02x:%02x:%02x",
             eth_header->ether_shost[0], eth_header->ether_shost[1],
             eth_header->ether_shost[2], eth_header->ether_shost[3],
             eth_header->ether_shost[4], eth_header->ether_shost[5]);
    json_object_set_new(root, "SourceMAC", json_string(source_mac));

    snprintf(dest_mac, sizeof(dest_mac), "%02x:%02x:%02x:%02x:%02x:%02x",
             eth_header->ether_dhost[0], eth_header->ether_dhost[1],
             eth_header->ether_dhost[2], eth_header->ether_dhost[3],
             eth_header->ether_dhost[4], eth_header->ether_dhost[5]);
    json_object_set_new(root, "DestinationMAC", json_string(dest_mac));

    // Check if it's an ARP packet
    if (ntohs(eth_header->ether_type) == ETHERTYPE_ARP) {

        // ARP header
        struct ether_arp *arp_header = (struct ether_arp *)(eth_header + 1);
        char source_ip[INET_ADDRSTRLEN], dest_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, arp_header->arp_spa, source_ip, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, arp_header->arp_tpa, dest_ip, INET_ADDRSTRLEN);
        json_object_set_new(root, "SourceIP", json_string(source_ip));
        json_object_set_new(root, "DestinationIP", json_string(dest_ip));

        json_object_set_new(root, "Protocol", json_string("ARP"));
    } else {
        // IP header
        json_object_set_new(root, "SourceIP", json_string(inet_ntoa(ip_header->ip_src)));
        json_object_set_new(root, "DestinationIP", json_string(inet_ntoa(ip_header->ip_dst)));

        // Print protocol
        switch (ip_header->ip_p) {
            case IPPROTO_TCP: {

                // TCP header
                struct tcphdr *tcp_header = (struct tcphdr *)(packet + sizeof(struct ether_header) + ip_header->ip_hl * 4);

                json_object_set_new(root, "Protocol", json_string("TCP"));
                char tcp_info[100];
                snprintf(tcp_info, sizeof(tcp_info), "%u->%u [ACK]: %u SEQ: %u Win: %u", ntohs(tcp_header->th_sport),
                         ntohs(tcp_header->th_dport), ntohl(tcp_header->th_ack), ntohl(tcp_header->th_seq),
                         ntohs(tcp_header->th_win));
                json_object_set_new(root, "Info", json_string(tcp_info));
                json_object_set_new(root, "SourcePort", json_integer(ntohs(tcp_header->th_sport)));
                json_object_set_new(root, "DestinationPort", json_integer(ntohs(tcp_header->th_dport)));
                break;
            }
            case IPPROTO_UDP: {
                json_object_set_new(root, "Protocol", json_string("UDP"));

                // UDP header
                struct udphdr *udp_header = (struct udphdr *)(packet + sizeof(struct ether_header) + ip_header->ip_hl * 4);
                char udp_info[100];
                snprintf(udp_info, sizeof(udp_info), "%u->%u", ntohs(udp_header->uh_sport), ntohs(udp_header->uh_dport));
                json_object_set_new(root, "Info", json_string(udp_info));
                json_object_set_new(root, "SourcePort", json_integer(ntohs(udp_header->uh_sport)));
                json_object_set_new(root, "DestinationPort", json_integer(ntohs(udp_header->uh_dport)));
                break;
            }
            case IPPROTO_ICMP:
                json_object_set_new(root, "Protocol", json_string("ICMP"));
                break;
            default:
                json_object_set_new(root, "Protocol", json_string("Unknown"));
        }
    }

    // Packet data - Hexadecimal and ASCII representation
    char hex_string[(pkthdr->len) * 2 + 1];  // Each byte represented by 2 characters + null terminator
    print_hex(packet, pkthdr->len, hex_string);
    json_object_set_new(root, "HexRepresentation", json_string(hex_string));

    char ascii_string[pkthdr->len + 1];  // Null terminator
    print_ascii(packet, pkthdr->len, ascii_string);
    json_object_set_new(root, "ASCIIRepresentation", json_string(ascii_string));

    // Print length of the packet
    json_object_set_new(root, "Length", json_integer(pkthdr->len));
    
    
    
    FILE *file;
    //Checking for end of file
    if(packet_count % MAX_PACKETS_PER_FILE == 0){
    
    	char filename[50];
        sprintf(filename, FILENAME_FORMAT, file_count);
        file = fopen(filename, "a");
        if (file == NULL) {
            fprintf(stderr, "Error opening file %s\n", filename);
            exit(EXIT_FAILURE);
        }
        
    	// Write last JSON object to the file
        fprintf(file, "%s,\n", json_dumps(root, JSON_COMPACT));

        // Release JSON object
    	json_decref(root);
        
       
    	// Write closing bracket of JSON array
        fprintf(file, "]\n");
        
        fclose(file);
        
        //Reopening to remove the trailing ','
        file = fopen(filename, "r+");
   	 if (file == NULL) {
        	perror("Error opening file");
        	exit(EXIT_FAILURE);
    	}

	//Make the file pointer to point the trailing ','
    	fseek(file, -4, SEEK_END);
    	
	//Replacing the ',' with ' '
    	fputc(' ', file);

    	// Close the file
    	fclose(file);

    	//printf("Trailing comma removed successfully.\n");
        
        //Printing the status
        printf("File %d Generated - %d packets processed\n",file_count,packet_count);
        
        // creating source path
        char src[100];
        sprintf(src, SRC_FORMAT, filename);
        //printf("%s\n",src);
        
        // creating destination format
        char dst[100];
        sprintf(dst, DST_FORMAT, filename);
        //printf("%s\n",dst);
        
        
        // Moving file to Activity folder
        if (rename(src, dst) == 0) {
        	printf("File %d moved successfully.\n",file_count);
        } else {
       	perror("Error moving file");
    	}
        
    	if(file_count < MAX_FILE_COUNT){
  		file_count++;
		char filename[50];
        	sprintf(filename, FILENAME_FORMAT, file_count);
        	//Opening new JSON file
        	file = fopen(filename, "w");
        	if (file == NULL) {
            		fprintf(stderr, "Error opening file %s\n", filename);
            		exit(EXIT_FAILURE);
       	 }
       	 // Write opening bracket of JSON array
        	fprintf(file, "[\n");
        	fclose(file);
        }
        else
        	exit(EXIT_FAILURE);
    }
    //Other than last Object
    else{
   	 char filename[50];
         sprintf(filename, FILENAME_FORMAT, file_count);
         file = fopen(filename, "a");
         if (file == NULL) {
            fprintf(stderr, "Error opening file %s\n", filename);
            exit(EXIT_FAILURE);
        }
        // Write JSON object to the file
        fprintf(file, "%s,\n", json_dumps(root, JSON_COMPACT));
        fclose(file);
        // Release JSON object
        json_decref(root);
   }
   

}
   
   

void packet_handler(unsigned char *user, const struct pcap_pkthdr *pkthdr, const unsigned char *packet) {
    // Create JSON object for the packet
    create_packet_json(pkthdr, (struct ether_header *)packet, (struct ip *)(packet + sizeof(struct ether_header)),
                       packet);
}


int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <interface>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;

    handle = pcap_open_live(argv[1], BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Could not open device %s: %s\n", argv[1], errbuf);
        exit(EXIT_FAILURE);
    }

    struct bpf_program fp;
    char filter_exp[] = "";
    if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "Could not parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        exit(EXIT_FAILURE);
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Could not install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        exit(EXIT_FAILURE);
    }

    // Open the first file in write mode (creates a new file or truncates an existing one)
    char filename[50];
    sprintf(filename, FILENAME_FORMAT, file_count);
    FILE *file = fopen(filename, "w");
    if (file == NULL) {
        fprintf(stderr, "Error opening file %s\n", filename);
        exit(EXIT_FAILURE);
    }
    // Write opening bracket of JSON array
    fprintf(file, "[\n");
    // Close the file
    fclose(file);

    // Start capturing packets
    pcap_loop(handle, 0, packet_handler, NULL);

    // Close the pcap handle
    pcap_close(handle);

    return 0;
}

