struct ipReturn {
    uint16_t nextProtocol;
    uint16_t ipHeaderLength;
    uint16_t ipPayloadLength;
};

struct L2Return{
    uint16_t dest_port;
    uint16_t src_port;
    uint16_t header_length;
};

////////////////////////////Protocols Supported //////////////////
uint16_t ethernet(FILE * fp, unsigned char * packet);

////////// layer 3 
void arp(FILE * fp, unsigned char * packet);

struct ipReturn myipv4(FILE * fp, unsigned char * packet);

struct ipReturn myipv6(FILE * fp, unsigned char * packet);

struct L2Return icmp(FILE * fp, unsigned char * packet);

//////////// layer 4
struct L2Return mytcp(FILE * fp, unsigned char * packet);

struct L2Return udp(FILE * fp, unsigned char * packet);

//////////// layer 5

void http(FILE *,unsigned char *);

void https(FILE * fp,unsigned char *packet, int start, int end);

void ssh(FILE *,unsigned char *);



