#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <openssl/sha.h>  //for sha1
#include <sys/time.h>

#include "receiver_tcp.h"
#include "Aufgabe2.h"



int main (int argc, char *argv[]) {

    int sockfd, newsockfd;  //socket file descriptor
    socklen_t cli_length;  //length of address
    int err;     //return value of bind for error handling
    struct sockaddr_in serv_addr, cli_addr/*, from*/;  //addresses for receiving and transmitting
    //socklen_t fromlen; //length of source address struct
    //int portno;
	
    //unsigned char headerstate;  //for parsing the id of each package

    char buff[BUFFERSIZE];  //mesage buffer
	
    unsigned short filenamelength;  //length of file name
    char *filename;  //name of file
    unsigned int filelength;  //length of file in bytes
    unsigned long receivedBytes; //Number of received data files (excluding header of each package!)

    struct stat folderstat = {0};  // to check if received folder exists
    char filepath[MAXPATHLENGTH];  //path to file in received folder with file name
    FILE* file;  //File stream to write file into
    unsigned long seqNr;  //number of packet received in data transmission
    //unsigned long readSeqNr;  //sequence number transmitted by sender
    //char *filebuffer; //holds the file content to write on file

    char *shaBuffer;  //holds the complete file payload accross all data packages
    char *shaPtr;  //for convenience, points to the next character to be written in shaBuffer
    char *shaVal;  //for the actual sha1-value
    char *recShaVal;  //received Sha1-Val
    char sha1_CMP;  //result of comparing sha-values according to task
	
    int i;

    struct timeval timeout;


    /****** CHECK INPUT ********/

	
    //error handling: argument parsing
    if (argc != 2) {
	printf("Illegal Arguments: [RECEIVER_PORT]");
	exit(1);
    }
	
	
    /******** SOCKET CREATION ***********/
	
    // AF_INET --> Protocol Family
    // SOCK_DGRAM --> Socket Type (UDP)
    // 0 --> Protocol Field of the IP-Header (0, TCP and UDP gets entered automatically)


    //portno = htons(atoi(argv[1]));
    
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
	printf(address_error);
	return 1;
    }

    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &(int){ 1 }, sizeof(int)) < 0)
    {
	printf("Socket could not be reused");
	return 1;
	//error("setsockopt(SO_REUSEADDR) failed");
    }
    
    
    // Clearing
    bzero((char*) &serv_addr, sizeof(serv_addr));

    //portno = htons(atoi(argv[1]));
    

    
    //CREATE TARGET ADDRESS
    // Assign Protocol Family
    serv_addr.sin_family = AF_INET;
    // Assign Port
    serv_addr.sin_port = htons(atoi(argv[1]));
    serv_addr.sin_addr.s_addr = INADDR_ANY;//inet_addr(/*INADDR_ANY*/"127.0.0.1");

    //bind socket to prepare receiving
    err = bind(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr));

    if (err < 0) {
	printf("Binding-Error");
	exit(1);
    }


    listen(sockfd, 1);

    cli_length = sizeof(cli_addr);
    
    newsockfd = accept(sockfd, (struct sockaddr *) &cli_addr, &cli_length);
    if(newsockfd < 0)
    {
	printf(address_error);
	return 1;
    }



    
    // Length of the Source Address Structure
    //fromlen = sizeof(struct sockaddr_in);


    /****** RECEIVE HEAD *******/
	
    timeout.tv_sec = WAIT;
    timeout.tv_usec = 0;

    // Set socket options for a possible timeout
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));


    err = read(newsockfd, buff, BUFFERSIZE);
    if (err< 0) {
	printf(timeout_error);
	exit(1);
    }

    //check if valid package received
    /*headerstate = (unsigned char) buff[0];
    if(headerstate != HEADER_T)
    {
	printf(packet_error);
	exit(1);
	}*/

    //go and parse the header
    parseHeader(buff, &filenamelength, &filename, &filelength);


    //print some parsed info from the header
    printf(filename_str, filename);
    printf(filesize_str,filelength);


    /*******  OPEN FILE OPERATIONS *******/

    //prepare Sha buffer. Will hold complete file so we can create sha1-value later
    shaBuffer = calloc(filelength,1);
    if(!shaBuffer)
    {
	printf("Could not allocate shaBuffer\n");
	return 1;
    }
	
    //this will be used to iterate on the shaBuffer
    shaPtr = shaBuffer;

	
    printf("Preparing file for writing...\n");

    //filename should not exceed limits. If it is too long there could be bufferoverflow, security issues, ...
    if(strlen(filename) + 10 > MAXPATHLENGTH)
    {
	printf("Can not create path: file name too long");
	return 1;
    }
	  
    //get file path
    snprintf(filepath, MAXPATHLENGTH, "%s%s", "received/", filename);
        

    //check if folder exists, create if it doesn't. Node: needs sudo-rights.
    if (!( stat("/received", &folderstat) == 0) && (S_ISDIR(folderstat.st_mode)) ){
	if (0!= mkdir("/received", 0700))
	{
	    printf("error when creating directory\n");
	    perror("mkdir");
	    return 1;
	}
    }
	
    //Open file, handle errors
    printf("Open file path %s\n", filepath);
    file = fopen(filepath, "w");
    if(!file)
    {
	printf("Illegal File");
	return 1;
    }


    /******* READ FILE TRANSMISSION *********/

    //initialise sequence number and number of received bytes
    seqNr = 0;
    receivedBytes = 0;

	
    printf("Standing by for incoming file...\n");
	

    /* start receiving and interpreting transmission
     * wait for each data package to be received, then parse it.
     * Check sequence number against received sequence number.
     * To properly read the actually received data of the file
     * write it into the shaBuffer. Once that is filled write the whole
     * shaBuffer to the hard drive.
     */
    do {
	err = read(newsockfd, buff, BUFFERSIZE);


	//read header state
	/*headerstate = (unsigned char) buff[0];
	if(headerstate != DATA_T)
	{
	    printf(packet_error);
	    printf("Wrong Headerstate in file transfer\n");
	    exit(1);
	    }*/

	//read sequence number
	/*readSeqNr =  (unsigned long) (  ( (unsigned char)buff[1] ) | ( ((unsigned char)buff[2]) << 8 ) | ( ((unsigned char)buff[3]) << 16 ) | ( ((unsigned char)buff[4]) << 24 ) );
	if(seqNr != readSeqNr)
	{
	    printf(order_error, readSeqNr, seqNr);
	    return 1;
	    }*/

	//set filebuffer to where the real buffer starts
	//filebuffer = buff;
	    
	for(i = 0; i<err; i++)
	{
	    if(shaPtr != shaBuffer + filelength)
	    {
		*(shaPtr++) = buff[i];
	    }
	}


	printf("Received %d payload bytes in packet %lu, writing now\n",err, seqNr);

	seqNr++;
	receivedBytes += err;  //received bytes must only store the number of bytes belonging to the data, not the head of the package

    }while(receivedBytes != filelength); //once we have received everything we're done


    //write current package to hard drive.
    fwrite(shaBuffer, 1, filelength, file);
	
    printf("File written on drive.\n");
	

    /******* RECEIVE SHA-1 ********/
        
    //receive sha-1
    err = read(newsockfd, buff, BUFFERSIZE);

    if(err != SHA_DIGEST_LENGTH*2 )
    {
	printf(SHA1_ERROR);
	printf("Wrong Sha-Package length\n");
	return 1;
    }


    //receive header
    /*headerstate = (unsigned char) buff[0];
    if(headerstate != SHA1_T)
    {
	printf(packet_error);
	printf("Wrong ID\n");
	exit(1);
	}*/

	
    recShaVal = calloc(SHA_DIGEST_LENGTH*2+1,1);
    if(!recShaVal)
    {
	printf("Could not allocate recShaVal space\n");
	return 1;
    }


    //parse Sha-value
    for(i = 0; i<SHA_DIGEST_LENGTH*2; i++)
    {
	recShaVal[i] = (unsigned char)buff[i];
    }
    recShaVal[SHA_DIGEST_LENGTH*2] = '\0';

    //calculate sha over received file

    shaVal = getSha1(shaBuffer, filelength);
    printf(receiver_sha1, shaVal);
    
    
    //compare results
    if(strcmp(shaVal, recShaVal) != 0 )
    {
	printf(SHA1_ERROR);
	sha1_CMP = SHA1_CMP_ERROR;
	    
    }
    else
    {
	printf(SHA1_OK);
	sha1_CMP = SHA1_CMP_OK;
    }


    /******* SEND SHA COMPARE RESULT ******/

    //prepare id
    //buff[0] = SHA1_CMP_T;

    //prepare compare result
    buff[0] = sha1_CMP;

    //sleep(1);

    //and away!
    err = write(newsockfd, buff, 1);
    if (err < 0) {
	printf("sendto-Error");
	exit(1);
    }


    /******* CLEAN UP ******/


    // Close Socket
    close(newsockfd);
    close(sockfd);
    fclose(file);
    free(filename);
    free(shaBuffer);
    free(recShaVal);
    free(shaVal);
	
    return 0;
}


void parseHeader(char* buffer, unsigned short *readnlength, char **readrealname, unsigned int *readfilelength)
{
    unsigned short i,j;
    
    char *readname;

    
    *readnlength = (unsigned short) (  ((unsigned char) buffer[0] ) | ( ((unsigned char) buffer[1]) << 8 ) );
    
   
    readname = calloc(*readnlength+1,1);

    
    //read name:
    for(i = 2; i<*readnlength+2; i++)
    {
	readname[i-2] = buffer[i];
    }


    *readrealname = readname;

    *readfilelength = 0;
    for(j = 0; j < 4; j++)
    {
	*readfilelength = *readfilelength | ( ( (unsigned char) buffer[i++])<<(j*8));
    }
    


}
