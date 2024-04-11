#include "imports.h"
#include "protocol_header.h"

void https(FILE * fp,unsigned char *packet, int start, int end){

    	    for (int i = start; i < end; i++) {
        	fprintf(fp,"%c ", packet[i]);
    		}
    	    fprintf(fp,"\n");

}
