#include "imports.h"
#include "protocol_header.h"
#include "utility_header.h"

// How to use : ./main.out -i interface_Name [-n number_Of_packets] [-p protocol_name]

int main(int argc, char *argv[]) {
    // Check if at least the program name and the interface name are provided
    if (argc < 3) {
        printUsage();
        return EXIT_FAILURE;
    }

    ////////////////////////////////// Parse command line arguments //////////////////
    struct Arguments args = parseArguments(argc, argv);

    // Print parsed arguments
    printf("Interface Name: %s\n", args.interfaceName);
    if (args.numberOfPackets != -1) {
        printf("Number of Packets: %d\n", args.numberOfPackets);
    }
    else{
    	args.numberOfPackets = 10;
    	printf("By default capturing %d number of Packets\n", args.numberOfPackets);
    }
    if (args.protocolName != NULL) {
        printf("Protocol Name: %s\n", args.protocolName);
    }
    else{
    	printf("By default capturing All types of Packets\n");
    }

//////////////////////////// Creating Socket for Receiving (Probiscus Mode)/////////////////
int sock_recv = createRawSocket(args.interfaceName,args.protocolName);


///////////////////////////////////// Printing Current System MAC IP///////////////////////
unsigned char Ip[INET6_ADDRSTRLEN];
unsigned char Mac[6];
getMacIp(sock_recv,args.interfaceName,Ip,Mac);

////////////////////////// Creating Files to Write /////////////////////////////////////////

    char mySendFilename[50];
    char myRecvFilename[50];
    char promiscuousFilename[50];

    // Generate filenames with current system time
    time_t currentTime = time(NULL);
    struct tm *localTime = localtime(&currentTime);
    strftime(mySendFilename, sizeof(mySendFilename), "mySend_%Y-%m-%d_%H-%M-%S.txt", localTime);
    strftime(myRecvFilename, sizeof(myRecvFilename), "myRecv_%Y-%m-%d_%H-%M-%S.txt", localTime);
    strftime(promiscuousFilename, sizeof(promiscuousFilename), "promiscuous_%Y-%m-%d_%H-%M-%S.txt", localTime);

    // Write text to each file
    writeToFile(mySendFilename, "This file contains the packets which is send out from your Pc\n");
    writeToFile(myRecvFilename, "This file contains the packets which is directed to your Pc\n");
    writeToFile(promiscuousFilename, "This file contains the packets meant for other users of your network\n");



/////////////////////////////////////////Receiving Packets//////////////////////////////////////////

    unsigned char* response = (unsigned char*) malloc(5000);//buffer to store response
    bzero(response,5000);
    int bytes_recv;
    uint16_t nextProtocol;
    FILE *file;
    // Prepare destination address
    struct sockaddr src_addr;
    socklen_t saddr_len = sizeof(src_addr);
    
    while(args.numberOfPackets--)
    {	
            
    	bzero(response,5000);
    	
    	saddr_len = sizeof(src_addr);
    if ((bytes_recv=recvfrom(sock_recv, response, (size_t)5000, 0, &src_addr, &saddr_len)) < 0)	{	
	perror("packet send failed");
	exit(EXIT_FAILURE);
    }
	
	if(checkMac(response,Mac,0) == 1){// dest Mac == My Mac (Write to myRecv)
		    file = fopen(myRecvFilename, "a"); // Open file in append mode
		    if (file == NULL) {
			perror("Error opening Recv file");
			exit(EXIT_FAILURE);
		    }
	}
	else if (checkMac(response,Mac,6) == 1){// src Mac == My Mac (Write to my)
		    file = fopen(mySendFilename, "a"); // Open file in append mode
		    if (file == NULL) {
			perror("Error opening Send file");
			exit(EXIT_FAILURE);
		    }
	}
	else{//Packet meant for others (Write to ProMisCuous File)
		    file = fopen(promiscuousFilename, "a"); // Open file in append mode
		    if (file == NULL) {
			perror("Error opening Promiscus file");
			exit(EXIT_FAILURE);
		    }
	}
	
	printPacket(file,response,0,bytes_recv);
	
	nextProtocol = ethernet(file,response);
	
	switch(nextProtocol){
		case 0x0806 : //arp
		fprintf(file,"\tNetwork Layer Protocol is ARP\n");
		break;
		case 0x0800 : //ipv4
		fprintf(file,"\tNetwork Layer Protocol is ipv4\n");
		break;
		case 0x86dd : //ipv6
		fprintf(file,"\tNetwork Layer Protocol is ipv6\n");
		break;
	}
	
	fclose(file); 
    }



    return EXIT_SUCCESS;
}

