#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/stat.h>  //for file stats
#include <unistd.h>    //for checking file access
#include <libgen.h>    //for getting file name
#include <openssl/sha.h>  //for sha1
#include <sys/time.h>

#include "Aufgabe2.h"
#include "sender_tcp.h"


int main (int argc, char *argv[]) {
	
    int sockfd, err;
    //int portno;
    //socklen_t clilength, length;
    struct sockaddr_in serv_addr;
    char buff[BUFFERSIZE];  //buffer for receiving messages (and later for sending as well)
    unsigned short nlength; //name length
    char *name;  //name of file
    unsigned int filelength; //actual file size
    size_t bufferlength;     //length of buffer that will be used for sending
    size_t readbytes;        //number of bytes read by fread
    int fd;                  //file descriptor for getting length
    FILE* file;              //file stream
    struct stat filebuf;     //file stats
    unsigned int seqNr;     //number of package to be sent
    //char filedatabuff[BUFFERSIZE-5];      //contains data of file
    int i;  //magic number that makes the program work.
    char *shaBuffer;  //holds the complete file across all data packages
    char *shaVal;   //holds the actual sha1-value
    char *shaPtr;

    struct timeval timeout;
        

    /****** CHECK INPUT ********/

    //check for right number of arguments
    if (argc != 4) {
	printf("Illegal Arguments: [RECEIVER_ADDRESS] [RECEIVER_PORT] [FILE PATH]");
	exit(1);
    }

    //check if file exists and can be read
    if( access(argv[3], R_OK) == -1 )
    {
	if( access(argv[3], F_OK) )
	{
	    printf("File does not exist");
	}
	else
	{
	    printf("No Read permission on file");
	}
	return 1;
    }


    /*******  OPEN FILE OPERATIONS *******/


    //Open file, handle errors
    file = fopen(argv[3], "r");
        
    if(!file)
    {
	printf("Illegal File");
	return 1;
    }


    //Get file descriptor
    fd = fileno(file);
    if(fd == 0)
    {
	printf("File reading error");
	return 1;
    }

    //Get file stats
    if(fstat(fd, &filebuf) != 0)
    {
	printf("File statistic read error");
	return 1;
    }


    /**** READ FILE STATS ****/
    //get length
    filelength = filebuf.st_size;

    //get file name without path
    name = basename(argv[3]);

    nlength = strlen(name);		




    
    /******** SOCKET CREATION ***********/
    // AF_INET --> Protocol Family
    // SOCK_DGRAM --> Socket Type (UDP)
    // 0 --> Protocol Field of the IP-Header (0, TCP and UDP gets entered automatically)
    sockfd = socket(AF_INET, SOCK_STREAM, 0);

    if (sockfd < 0) {
	printf("Socket-Error");
	exit(1);
    }

    // Clearing
    bzero(buff, BUFFERSIZE);
    bzero((char*) &serv_addr, sizeof(serv_addr));



    //CREATE TARGET ADDRESS
    // Assign Protocol Family
    serv_addr.sin_family = AF_INET;
    // Assign Port
    serv_addr.sin_port = htons(atoi(argv[2]));
    // Address of the Receiver (Dotted to Network)
    serv_addr.sin_addr.s_addr = inet_addr(argv[1]);
	
    // Length of the Address Structure
    //length = sizeof(struct sockaddr_in);



    if(connect(sockfd, (struct sockaddr*) &serv_addr, sizeof(serv_addr))<0)
    {
	printf(address_error);
	return 1;
    }
    
    
			       
    
	

    
    /********* HEADER SENDING *********/

    // To satisfy the MTU of a PPPoE-Connection (max package size)
    if ((bufferlength = nlength + 6) > BUFFERSIZE) {
	printf("Exceeded maximum package size.");
	return 1;
    }


    prepareHeader(buff, nlength, name, filelength);
    printf(filename_str, name);
    printf(filesize_str,filelength);
	
    printf("Standby for sending of header...\n");
        
    //send
    err = write(sockfd, buff, bufferlength);
    //handle sending errors
    if (err < 0) {
	printf("sendto-Error");
	exit(1);
    }
    printf("Sent %d bytes\n", err);


    /******* FILE TRANSFER ********/

    //reset sequence number
    seqNr = 0;

    //prepare Sha
    shaBuffer = calloc((size_t)	filelength, 1);
    if(!shaBuffer)
    {
	printf("Could not allocate shaBuffer\n");
	return 1;
    }
    shaPtr = shaBuffer;

	
    printf("Commencing file transmission\n");
    do {
	//buff[0] = DATA_T;  //Yes, we're sending data!

	//put sequence number into next 4 bytes of buffer
	/*for(i = 1; i < 5; i++)
	{
		
	    buff[i] = (char) ( (seqNr >> ( (i-1)*8) ) & 0xff );
	    }*/

	    

	//check how many files could be read. Is less than BUFFERSIZE-5 when eof is reached
	readbytes = fread(buff, 1, BUFFERSIZE, file);


	//transmit if we have any bytes to transmit
	if(readbytes != 0)
	{
	    //put filebuffer into real buffer. Can't concat because buff is not really a string and can have null anywhere...
	    for(i = 0; i<readbytes; i++)
	    {
		*(shaPtr++)=buff[i];
	    }

	    //Send data.

	    err = write(sockfd, buff, readbytes);
	    if( err != readbytes )
	    {
		printf("Sending data package %d failed",seqNr);
		return 1;
	    }

	    printf("Sent package %d containing %zu bytes\n", seqNr, readbytes);
	}
	seqNr++;
	    
    }while(readbytes == BUFFERSIZE);  //once readbytes is less than BUFFERSIZE eof was reached and we're finished.
	

    printf("File transmission complete\n");


    /******* SHA-1 ********/

    //if we don't do this then valgrind on the receiver causes the program to slow down too much to still get this
    sleep(2);
    
    printf("Calculating Sha1...\n");

    //calculate sha-1
    shaVal = getSha1(shaBuffer, filelength);
    printf(sender_sha1, shaVal);

    
    
    //prepare transmitting of sha-1
    //buff[0] = SHA1_T;

    for(i = 0; i<SHA_DIGEST_LENGTH*2; i++)
    {
	buff[i] = shaVal[i];
    }

    //transmit sha-1
	
    err = write(sockfd, buff, SHA_DIGEST_LENGTH*2);
    if( err != SHA_DIGEST_LENGTH*2 )
    {
	printf("Error when sending SHA1");
	return 1;
    }

    printf(SHA1_OK);


    /****** RECEIVE SHA COMPARE RESULT ******/

    timeout.tv_sec = WAIT;
    timeout.tv_usec = 0;
    // Set socket options for a possible timeout
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

    //receive sha comp result
    err = read(sockfd, buff, BUFFERSIZE);
    if (err != 1)
    {
	printf(timeout_error);
	exit(1);
    }

    //check header
    /*if((unsigned char)buff[0] !=  SHA1_CMP_T)
    {
	printf(SHA1_ERROR);
	}*/

    //check actual compare result
    if( (unsigned char)buff[0]  == SHA1_CMP_ERROR)
    {

	printf(SHA1_ERROR);
    }
    else
    {
	printf(SHA1_OK);
    }
	

    /******** CLEAN UP *******/

	
    // Close Socket
    close(sockfd);
    fclose(file);
    free(shaBuffer);
    free(shaVal);
	
    return 0;
}

	    

void prepareHeader(char *buffer, unsigned short nlength, char *name, unsigned int filelength)
{

    unsigned short i,j;

    //TYPE-ID
    //buffer[0] = (char) HEADER_T;

    //name-length
    buffer[0] = (char) (nlength & 0xff);
    buffer[1] = (char) ((nlength >> 8) & 0xff);


    //name
    for(i=2; i<nlength+2; i++)
    {
	buffer[i] = name[i-2];
    }


    //filesize
    for(j = 0; j < 4; j++)
    {
	buffer[i++] = (char) ( (filelength >> (j*8) ) & 0xff );
    }

}
