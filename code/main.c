#include "imports.h"
#include "protocol_header.h"
#include "utility_header.h"

//global variables
struct Arguments args;


// signal handler
void handle_signal(int signo){
	if(signo == SIGINT){
		args.numberOfPackets = 1;
	}

}

// How to use : ./fbi -i interface_Name [-n number_Of_packets] [-p protocol_name]
int main(int argc, char *argv[]) {
    // Check if at least the program name and the interface name are provided
    if (argc < 3) {
        printUsage();
        return EXIT_FAILURE;
    }
	
    signal(SIGINT, handle_signal); 
	 
    ////////////////////////////////// Parse command line arguments //////////////////
    args = parseArguments(argc, argv);
	
    // Print parsed arguments
    if (args.numberOfPackets != -1) {
        printf("\nNumber of Packets to be Captured : %d\n", args.numberOfPackets);
    }
    else{
    	printf("\nBy default capturing Packets until Press Ctrl + C\n");
    }
    if (args.protocolName != NULL) {
        printf("Type of Packets to be Captured: %s\n", args.protocolName);
    }
    else{
    	printf("By default capturing All types of Packets\n");
    }
    
////////////////////////////////// Setting the filters as per -p [protocol Name] /////////////

// flags used for filter protocols
unsigned char l3flags[3];
unsigned char l4flags[3];
unsigned char l5flags[7];

//setting the flags as
setFilterFlags(l3flags,l4flags,l5flags,&args);	
		
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
    strftime(mySendFilename, sizeof(mySendFilename), "mySend_%Yy-%mm-%dd_%Hhr-%Mmin-%Ssec.txt", localTime);
    strftime(myRecvFilename, sizeof(myRecvFilename), "myRecv_%Yy-%mm-%dd_%Hhr-%Mmin-%Ssec.txt", localTime);
    strftime(promiscuousFilename, sizeof(promiscuousFilename), "promiscuous__%Yy-%mm-%dd_%Hhr-%Mmin-%Ssec.txt", localTime);

    // Write text to each file
    writeHeaderToFile(mySendFilename, "This file contains the packets which is send out from your Pc\n",Ip,Mac,args.interfaceName);
    writeHeaderToFile(myRecvFilename, "This file contains the packets which is directed to your Pc\n",Ip,Mac,args.interfaceName);
    writeHeaderToFile(promiscuousFilename, "This file contains the packets meant for other users of your network\n",Ip,Mac,args.interfaceName);



/////////////////////////////////////////Receiving Packets//////////////////////////////////////////
    printf("Started Sniffing ....\n........\n");
    unsigned char* response = (unsigned char*) malloc(5000);//buffer to store response
    bzero(response,5000);
    int bytes_recv;
    uint16_t nextProtocol;
    struct ipReturn IpRet;
    struct L2Return L2Ret;
    FILE *file;
    // Prepare destination address
    struct sockaddr src_addr;
    socklen_t saddr_len = sizeof(src_addr);
    
    int flag  = 0; // denotes that if we have printed the asked protcol or not
    // if flag == 1 then args.numberOfPackets--
    while(args.numberOfPackets!=0)
    {	
        flag=0;    
    	bzero(response,5000);
    	
    	saddr_len = sizeof(src_addr);
	if((bytes_recv=recvfrom(sock_recv, response,(size_t)5000, 0, &src_addr, &saddr_len)) < 0){	
		perror("packet recv failed");
		exit(EXIT_FAILURE);
	}
	
	/////////////////////////////////////////////////////////////////////////////
	
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
	
	fprintf(file,"\n-------------------------------------------------------------------------------------------------\n\tByte by Byte (Hex form) representation of Packet :\n");
	printPacket(file,response,0,bytes_recv);
	
	nextProtocol = ethernet(file,response);
	
  //////////////////////////////////////////////////////////////////////////////////
  
	if (nextProtocol == 0x0806 && l3flags[ARP_FLAG_IND] == 1) { // arp
	
	    
	    fprintf(file, "\tNext Layer Protocol is ARP\n");
	    arp(file, &response[14]);
	    fclose(file);
	    args.numberOfPackets--;
	    continue;
	    
	} else if (nextProtocol == 0x0800 && l3flags[IPV4_FLAG_IND] == 1) { // ipv4
	
	
	    fprintf(file, "\tNext Layer Protocol is ipv4\n");
	    IpRet = myipv4(file, &response[14]);
	    flag = 1;
	    
	} else if (nextProtocol == 0x86dd && l3flags[IPV6_FLAG_IND] == 1) { // ipv6
	
	    
	    fprintf(file, "\tNext Layer Protocol is ipv6\n");
	    IpRet = myipv6(file, &response[14]);
	    flag = 1;
	    
	} else {
	
	    fprintf(file,"\nAnalysis Of Packet Dropped\n");	    
	    //printPacket(file, response, 14, bytes_recv);
	    fclose(file);
	    //args.numberOfPackets--;
	    continue;
	}
 
  ///////////////////////////////////////////////////////////////////////////////////
	
	// nextProtocol opcode is from 0x00 to 0xff
	if (IpRet.nextProtocol == 0x0006 && l4flags[TCP_FLAG_IND] == 1) { // tcp
	
	    fprintf(file, "\tNext Layer Protocol is TCP\n");
	    L2Ret = mytcp(file, &response[14 + IpRet.ipHeaderLength]);
	    flag=1;	    
	} 
	else if (IpRet.nextProtocol == 0x0011 && l4flags[UDP_FLAG_IND] == 1) { // udp
	
	    fprintf(file, "\tNext Layer Protocol is UDP\n");
	    L2Ret = udp(file, &response[14 + IpRet.ipHeaderLength]);
	    flag=1;	    
	} 
	else if (IpRet.nextProtocol == 0x003A) { // ipv6-icmp
	
	    fprintf(file, "\tNext Layer Protocol is ipv6-icmp\n");
	    L2Ret = icmp(file, &response[14 + IpRet.ipHeaderLength]);
	    fclose(file);
	    args.numberOfPackets--;
	    continue;
	} 
	else if (IpRet.nextProtocol == 0x0001 && l4flags[ICMP_FLAG_IND] == 1) { // icmp
	
	    fprintf(file, "\tNext Layer Protocol is icmp\n");
	    L2Ret = icmp(file, &response[14 + IpRet.ipHeaderLength]);
	    fclose(file);
	    args.numberOfPackets--;
	    continue;
	} 
	else {
	
	    //fprintf(file,"\nNext Layer Protocol not Supported or Packet Doesnt Match Filter\n\tThe following is L3 payload :\n");
	    //printPacket(file, response, 14 + IpRet.ipHeaderLength, bytes_recv);
	    fprintf(file,"\nAnalysis Of Packet Dropped\n");
	    fclose(file);
	    //args.numberOfPackets--;
	    continue;
	}

 ///////////////////////////////////////////////////////////////////////////////////////////	
	
	//14 is ethernet header lentgth and bytes_recv is the total packet size
	fprintf(file,"\nApplication Layer Protocol Analysis of the above packet\n");
	
	    if ((L2Ret.dest_port == 80 || L2Ret.src_port == 80) && l5flags[HTTP_FLAG_IND] ==1) {
	    	flag = 1;
		fprintf(file, "\t:HTTP Header\n");
		http(file,&response[14+IpRet.ipHeaderLength+L2Ret.header_length]);
	    } 
	    else if ((L2Ret.dest_port == 443 || L2Ret.src_port == 443)&& l5flags[HTTPS_FLAG_IND] ==1) {
	    	flag=1;
		fprintf(file, "\t:HTTPS Header\n");
	
	// 4 ways to print (last 3 not working)
		
	     //printPacket(file,response,(14+IpRet.ipHeaderLength+L2Ret.header_length),bytes_recv);
		//fprintf(file,"%s\n",&response[14+IpRet.ipHeaderLength+L2Ret.header_length]);
		//http(file,&response[14+IpRet.ipHeaderLength+L2Ret.header_length]);
		//https(file,response,(14+IpRet.ipHeaderLength+L2Ret.header_length),bytes_recv);
	    } 
	    else if ((L2Ret.dest_port == 23 || L2Ret.src_port == 23) && l5flags[TELNET_FLAG_IND] ==1) {
	    	flag =1;
		fprintf(file, "\t:Telnet Header\n");
	    } 
	    else if ((L2Ret.dest_port == 20 || L2Ret.src_port == 20 || L2Ret.dest_port == 21 || L2Ret.src_port == 21) && l5flags[FTP_FLAG_IND] ==1){
	    	flag =1;
		fprintf(file, "\t:FTP Header\n");
	    } 
	    else if((L2Ret.dest_port == 25 || L2Ret.src_port == 25) && l5flags[SMTP_FLAG_IND] ==1){
		flag=1;
		fprintf(file, "\t:SMTP Header\n");
	    } 
	    else if ((L2Ret.dest_port == 53 || L2Ret.src_port == 53) && l5flags[DNS_FLAG_IND] ==1){
		flag=1;
		fprintf(file, "\t:DNS Header\n");
	    }
	    else if ((L2Ret.dest_port == 22 || L2Ret.src_port == 22) && l5flags[SSH_FLAG_IND] ==1){
		flag=1;
		fprintf(file, "\t:SSH Header\n");
	    }
	    else {
		fprintf(file, "\t:Protocol not Supported \n");
		//printing App layer PDU    
	       printPacket(file,response,(14+IpRet.ipHeaderLength+L2Ret.header_length),bytes_recv);
	    }
	        
    	// update condn for while loop
    	if(flag) args.numberOfPackets--;
    	else fprintf(file, "\nPacket Dropped As Not Per Filter \n");
    	
    	fclose(file); 
    
    }// end of while loop
    
    printf("Packet Sniffing Complete... 3 reports(.txt files) created...\n\n");
    return EXIT_SUCCESS;
}
