#include "imports.h"
#include "protocol_header.h"

void http(FILE *output,unsigned char *header) {
    char *line;
    char *field_name;
    char *field_value;

    // Tokenize header by '\n' to extract each line
    line = strtok(header, "\n");

    // Loop through each line until NULL is encountered
    while (line != NULL) {
        // Extract field name and value
        field_name = strtok(line, ":");
        field_value = strtok(NULL, "\r\n");

        // Print field name and value to the output file
        if (field_name != NULL && field_value != NULL) {
            fprintf(output, "%s: %s\n", field_name, field_value);
        }

        // Move to the next line
        line = strtok(NULL, "\n");
    }
}



