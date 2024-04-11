#include "imports.h"
#include "protocol_header.h"
#include "utility_header.h"


struct L2Return icmp(FILE *fp, unsigned char *packet) {

    fprintf(fp,"\nNetwork Layer Protocol Analysis of the above packet\n");
    fprintf(fp,"\t:Icmp Header\n");

    uint8_t type = packet[0]; // Type field
    uint8_t code = packet[1]; // Code field
    uint16_t checksum = (packet[2] << 8) | packet[3]; // Checksum field

    fprintf(fp, "ICMP Header:\n");

    switch (type) {
        
        case 0: // Echo Reply
            fprintf(fp, "  Type: %u -- Echo reply\n", type);
	    fprintf(fp, "  Code: %u\n", code);
	    fprintf(fp, "  Checksum: 0x%04X\n", checksum);
            fprintf(fp, "  Identifier: %02X%02X\n", packet[4], packet[5]);
            fprintf(fp, "  Sequence Number: %02X%02X\n", packet[6], packet[7]);
            break;
        
        
        case 3: // Destination Unreachable
            fprintf(fp, "  Type: %u -- Destination Unreachable\n", type);
	    fprintf(fp, "  Code: %u\n", code);
            switch (code) {
                case 0:
                    fprintf(fp, "  Code: %u --Network Unreachable\n", code);
                    break;
                case 1:
                    fprintf(fp, "  Code: %u --Host Unreachable\n", code);
                    break;
                case 2:
                    fprintf(fp, "  Code: %u --Protocol Unreachable\n", code);
                    break;
                case 3:
		        fprintf(fp, "  Code: %u --Port Unreachable\n", code);
	 		break;
                case 4:
		        fprintf(fp, "  Code: %u --Fragmentation Needed and DF Set\n", code);
		        break;
                case 5:
                     fprintf(fp, "  Code: %u --Source Route Failed\n", code);
                     break;
                default:
                	fprintf(fp, "  Code: %u -- Unknown\n", code);
                        break;
            }
            fprintf(fp, "  Checksum: 0x%04X\n", checksum);
            fprintf(fp, "  Unused: %02X%02X\n", packet[4], packet[5]);
            fprintf(fp, "  Next-Hop MTU: %02X%02X\n", packet[6], packet[7]);

            break;
        
        
        
        case 4: // Source Quench
            fprintf(fp, "  Type: %u --Source Quench\n", type);
	    fprintf(fp, "  Code: %u\n", code);
	    fprintf(fp, "  Checksum: 0x%04X\n", checksum);      
            fprintf(fp, "  Unused: %02X%02X%02X%02X\n", packet[4], packet[5], packet[6], packet[7]); // 4 bytes of Unused
            
            fprintf(fp, "  Original IP Header:\n");
            fprintf(fp, "    Version: %u\n", (packet[8] >> 4) & 0x0F);
            fprintf(fp, "    Header Length: %u bytes\n", (packet[8] & 0x0F) * 4);
            fprintf(fp, "    Type of Service: 0x%02X\n", packet[9]);
            fprintf(fp, "    Total Length: %u\n", (packet[10] << 8) | packet[11]);
            fprintf(fp, "    Identification: 0x%02X%02X\n", packet[12], packet[13]);
            fprintf(fp, "    Flags: 0x%02X\n", (packet[14] >> 5) & 0x07);
            fprintf(fp, "    Fragment Offset: %u\n", ((packet[14] & 0x1F) << 8) | packet[15]);
            fprintf(fp, "    Time to Live: %u\n", packet[16]);
            fprintf(fp, "    Protocol: %u\n", packet[17]);
            fprintf(fp, "    Header Checksum: 0x%04X\n", (packet[18] << 8) | packet[19]);
            fprintf(fp, "    Source IP Address: %u.%u.%u.%u\n", packet[20], packet[21], packet[22], packet[23]);
            fprintf(fp, "    Destination IP Address: %u.%u.%u.%u\n", packet[24], packet[25], packet[26], packet[27]);
            
          fprintf(fp, "    64 bits of Original Data DataGram :%02x %02x %02x %02x %02x %02x %02x %02x\n", packet[28], packet[29], packet[30], packet[31],packet[32],packet[33],packet[34],packet[35]);
            break;
        
        
        
        case 5: // Redirect Message
            fprintf(fp, "  Type: %u --Redirect Message\n", type);	  
            
            switch (code) {
                case 0:
                fprintf(fp, "  Code: %u -- Redirect Datagram for the Network\n", code);
                    
                    break;
                case 1:
                fprintf(fp, "  Code: %u -- Redirect Datagram for the Host\n", code);
              
                    break;
                case 2:
                fprintf(fp, "  Code: %u -- Redirect Datagram for Type of Service and Network\n", code);           
                    break;
                case 3:
                fprintf(fp, "  Code: %u -- Redirect Datagram for the Type of Service and Host\n", code);
          
                    break;
                default:
                fprintf(fp, "  Code: %u -- Unknown\n", code);
                  
                    break;
            }
            fprintf(fp, "  Checksum: 0x%04X\n", checksum);
            fprintf(fp, "  Gateway IP Address: %u.%u.%u.%u\n", packet[4], packet[5], packet[6], packet[7]);

            break;
        
        
        case 8: // Echo Request
            fprintf(fp, "  Type: %u -- Echo Request\n", type);
	    fprintf(fp, "  Code: %u\n", code);
	    fprintf(fp, "  Checksum: 0x%04X\n", checksum);
            fprintf(fp, "  Identifier: %02X%02X\n", packet[4], packet[5]);
            fprintf(fp, "  Sequence Number: %02X%02X\n", packet[6], packet[7]);
            // Add more fields if needed
            break;
        
        
        case 11: // Time Exceeded
            fprintf(fp, "  Type: %u -- Time Exceeded\n", type);
            switch (code) {
                case 0:
                    fprintf(fp, "  Code: %u --Time to Live exceeded in transit\n",code);
                    break;
                case 1:
                    fprintf(fp, "  Code: %u --Fragment reassembly time exceeded\n",code);
                    break;
                default:
                    fprintf(fp, "  Code: %u --Unknown\n",code);
                    break;
            }
            
            fprintf(fp, "  Checksum: 0x%04X\n", checksum);
            // Remaining fields of Time Exceeded
            fprintf(fp, "  Unused: %02X%02X%02X%02X\n", packet[4], packet[5], packet[6], packet[7]); // 4 bytes of Unused
            // Add more fields if needed
            break;
        
        
        case 12: // Parameter Problem
            fprintf(fp, "  Type: %u -- Parameter Problem\n",type);
            switch (code) {
                case 0:
                    fprintf(fp, "  Code: %u --Pointer indicates the error\n",code);
                    break;
                case 1:
                    fprintf(fp, "  Code: %u -- Missing a required option\n",code);
                    break;
                case 2:
                    fprintf(fp, "  Code: %u -- Bad length\n",code);
                    break;
                default:
                    fprintf(fp, "  Code: %u -- Unknown\n",code);
                    break;
            }
            fprintf(fp, "  Checksum: 0x%04X\n", checksum);
            fprintf(fp, "  Pointer: %u\n", packet[4]);
            // Remaining fields of Parameter Problem
            fprintf(fp, "  Unused: %02X%02X\n", packet[5], packet[6]);
            // Add more fields if needed
            break;
        
        
        case 13: // Timestamp Request
            fprintf(fp, "  Type: %u --Timestamp Request\n",type);
            fprintf(fp, "  Code: %u\n", code);
	    fprintf(fp, "  Checksum: 0x%04X\n", checksum);
            fprintf(fp, "  Identifier: %02X%02X\n", packet[4], packet[5]);
            fprintf(fp, "  Sequence Number: %02X%02X\n", packet[6], packet[7]);
            fprintf(fp, "  Originate Timestamp: %02X%02X%02X%02X\n", packet[8], packet[9], packet[10], packet[11]);
            fprintf(fp, "  Receive Timestamp: %02X%02X%02X%02X\n", packet[12], packet[13], packet[14], packet[15]);
            fprintf(fp, "  Transmit Timestamp: %02X%02X%02X%02X\n", packet[16], packet[17], packet[18], packet[19]);
            // Add more fields if needed
            break;
        
        
        case 14: // Timestamp Reply
            fprintf(fp, "  Type: %u --Timestamp Reply\n",type);
            fprintf(fp, "  Code: %u\n", code);
	    fprintf(fp, "  Checksum: 0x%04X\n", checksum);
            fprintf(fp, "  Identifier: %02X%02X\n", packet[4], packet[5]);
            fprintf(fp, "  Sequence Number: %02X%02X\n", packet[6], packet[7]);
            fprintf(fp, "  Originate Timestamp: %02X%02X%02X%02X\n", packet[8], packet[9], packet[10], packet[11]);
            fprintf(fp, "  Receive Timestamp: %02X%02X%02X%02X\n", packet[12], packet[13], packet[14], packet[15]);
            fprintf(fp, "  Transmit Timestamp: %02X%02X%02X%02X\n", packet[16], packet[17], packet[18], packet[19]);
            // Add more fields if needed
            break;
        
        
        case 15: // Information Request
            fprintf(fp, "  Type: %u --Information Request\n",type);
            fprintf(fp, "  Code: %u\n", code);
	    fprintf(fp, "  Checksum: 0x%04X\n", checksum);
            fprintf(fp, "  Identifier: %02X%02X\n", packet[4], packet[5]);
            fprintf(fp, "  Sequence Number: %02X%02X\n", packet[6], packet[7]);
            // Add more fields if needed
            break;
        
        
        case 16: // Information Reply
            fprintf(fp, "  Type: %u --Information Reply\n",type);
            fprintf(fp, "  Code: %u\n", code);
	    fprintf(fp, "  Checksum: 0x%04X\n", checksum);
            fprintf(fp, "  Identifier: %02X%02X\n", packet[4], packet[5]);
            fprintf(fp, "  Sequence Number: %02X%02X\n", packet[6], packet[7]);
            // Add more fields if needed
            break;
        
        default:
            fprintf(fp, "  ICMP Type: Unknown\n");
            break;
    }
    
    struct L2Return ret;
    ret.src_port = 0;
    ret.dest_port = 0;
    ret.header_length = 0;
    return ret;
}


