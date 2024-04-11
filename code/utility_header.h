
// giving l3 protcols index in the filter array
#define L3_FLAG_LEN     3
#define ARP_FLAG_IND    0
#define IPV4_FLAG_IND   1
#define IPV6_FLAG_IND   2

// giving l4 protcols index in the filter array
#define L4_FLAG_LEN     3
#define ICMP_FLAG_IND   0
#define TCP_FLAG_IND    1
#define UDP_FLAG_IND    2

// giving l5 protcols index in the filter array
#define L5_FLAG_LEN     7
#define HTTP_FLAG_IND   0
#define HTTPS_FLAG_IND  1
#define TELNET_FLAG_IND 2
#define FTP_FLAG_IND    3
#define SMTP_FLAG_IND   4
#define DNS_FLAG_IND    5
#define SSH_FLAG_IND    6

// Define a structure to hold the parsed arguments
struct Arguments {
    char* interfaceName;
    int numberOfPackets;
    char* protocolName;
};

// All the below function implementation is present in the utils.c file

void printUsage(); // Prints the correct way to run fbi

struct Arguments parseArguments(int argc, char *argv[]);//for cli_parsing

int createRawSocket(const char* interfaceName,const char* protocolName);

void getMacIp(int sock_recv,char * interfaceName,unsigned char *Ip,unsigned char *Mac);

void writeHeaderToFile(const char *filename, const char *text,unsigned char *Ip,unsigned char * Mac,char * interfaceName);

void printPacket(FILE * fp,unsigned char *packet, int start, int end);

int checkMac(unsigned char* packet,const unsigned char *mac,int start);

void setFilterFlags(unsigned char *, unsigned char * , unsigned char *, struct Arguments * args);


