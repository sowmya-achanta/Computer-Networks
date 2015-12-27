/*********NETCAT_PART- SOCKET PROGRAMMING**********************/
/*********Authors: Jagadeesh Madagundi, Sowmya Achanta ********/
/***This program will transfer data from client to server over Internet*****/
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
 
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <time.h>

#include <openssl/hmac.h> // need to add -lssl to compile

#define BUFSIZE 4096

static const int MAXPENDING = 5; // Maximum outstanding connection requests

/** shared Key**/
static const char key[16] = { 0x0e, 0x3f, 0x28, 0x61, 0xba, 0xa9,
0x9b, 0x28, 0x72, 0xd3, 0x5c, 0xcc, 0xe2, 0x01, 0x17, 0xfa };
int keylen = sizeof(key);

/**
 * Structure to hold all relevant state
 **/
typedef struct nc_args{
  struct sockaddr_in destaddr; //destination/server address
  unsigned short port; //destination/listen port
  unsigned short listen; //listen flag
  int n_bytes; //number of bytes to send
  int offset; //file offset
  int verbose; //verbose output info
  int message_mode; // retrieve input to send via command line
  char * message; // if message_mode is activated, this will store the message
  char * filename; //input/output file
}nc_args_t;

void DieWithUserMessage(const char *msg, const char *detail);
void DieWithSystemMessage(const char *msg);
void launchServer(nc_args_t *nc_args);
void launchClient(nc_args_t *nc_args);

/**
 * usage(FILE * file) -> void
 *
 * Write the usage info for netcat_part to the give file pointer.
 */
void usage(FILE * file){
  fprintf(file,
         "netcat_part [OPTIONS]  dest_ip [file] \n"
         "\t -h           \t\t Print this help screen\n"
         "\t -v           \t\t Verbose output\n"
	     "\t -m \"MSG\"   \t\t Send the message specified on the command line. \n"
	     "                \t\t Warning: if you specify this option, you do not specify a file. \n"
         "\t -p port      \t\t Set the port to connect on (dflt: 6767)\n"
         "\t -n bytes     \t\t Number of bytes to send, defaults whole file\n"
         "\t -o offset    \t\t Offset into file to start sending\n"
         "\t -l           \t\t Listen on port instead of connecting and write output to file\n"
         "                \t\t and dest_ip refers to which ip to bind to (dflt: localhost)\n"
         );
}

/**
 * Given a pointer to a nc_args struct and the command line argument
 * info, set all the arguments for nc_args to function use getopt()
 * procedure.
 *
 * Return:
 *     void, but nc_args will have return results
 **/
void parse_args(nc_args_t * nc_args, int argc, char * argv[]){
  int ch;
  struct hostent * hostinfo;
  //set defaults
  nc_args->n_bytes = 0;
  nc_args->offset = 0;
  nc_args->listen = 0;
  nc_args->port = 6767;
  nc_args->verbose = 0;
  nc_args->message_mode = 0;
 
  while ((ch = getopt(argc, argv, "lm:hvp:n:o:")) != -1) {
    switch (ch) {
    case 'h': //help
      usage(stdout);
      exit(0);
      break;
    case 'l': //listen
      nc_args->listen = 1;
      break;
    case 'p': //port
      nc_args->port = atoi(optarg);
      break;
    case 'o'://offset
      nc_args->offset = atoi(optarg);
      break;
    case 'n'://bytes
      nc_args->n_bytes = atoi(optarg);
      break;
    case 'v':
      nc_args->verbose = 1;
      break;
    case 'm':
      nc_args->message_mode = 1;
      nc_args->message = malloc(strlen(optarg)+1);
      strncpy(nc_args->message, optarg, strlen(optarg)+1);
      break;
    default:
      fprintf(stderr,"ERROR: Unknown option '-%c'\n",ch);
      usage(stdout);
      exit(1);
    }
  }
 
  argc -= optind;
  argv += optind;
 
  if (argc < 2 && nc_args->message_mode == 0){
    fprintf(stderr, "ERROR: Require ip and file\n");
    usage(stderr);
    exit(1);
  } else if (argc != 1 && nc_args->message_mode == 1) {
    fprintf(stderr, "ERROR: Require ip send/recv from when in message mode\n");
    usage(stderr);
    exit(1);
  }
 
  if(!(hostinfo = gethostbyname(argv[0]))){
    fprintf(stderr,"ERROR: Invalid host name %s",argv[0]);
    usage(stderr);
    exit(1);
  }

  nc_args->destaddr.sin_family = hostinfo->h_addrtype;
  bcopy((char *) hostinfo->h_addr,
        (char *) &(nc_args->destaddr.sin_addr.s_addr),
        hostinfo->h_length);
   
  nc_args->destaddr.sin_port = htons(nc_args->port);
   
  /* Save file name if not in message mode */
  if (nc_args->message_mode == 0) {
    nc_args->filename = malloc(strlen(argv[1])+1);
    strncpy(nc_args->filename,argv[1],strlen(argv[1])+1);
  }

 }

int main(int argc, char * argv[]){
nc_args_t nc_args;

//initializes the arguments struct for your use
parse_args(&nc_args, argc, argv);

if (nc_args.listen == 1)
	launchServer(&nc_args);
else if (nc_args.message_mode == 0 || nc_args.message_mode == 1)
	launchClient(&nc_args);

return 0;
}

void launchClient(nc_args_t *nc_args)
{
	char *filename = nc_args->filename;		
	int  offset = nc_args->offset;
	int  numBytes = nc_args->n_bytes;
	FILE *fp;
	long lSize;
	char buffer[BUFSIZE];
	char block[100];
	size_t result;

	// Create a reliable, stream socket using TCP
	int sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sock < 0)
		DieWithSystemMessage("socket() failed");

	// Establish  connection to the  server
	if (nc_args->verbose == 1)
		printf("Connecting to the server...\n");
	if (connect(sock, (struct sockaddr *) &nc_args->destaddr, sizeof(nc_args->destaddr)) < 0)
		DieWithSystemMessage("connect() failed");
	if (nc_args->verbose == 1)
	{
		printf("Connection established\n");
		printf("Sending packets....\n");
	}

	if (nc_args->message_mode == 1)
	{

		// obtain msg size:
		lSize = strlen(nc_args->message);

		if (numBytes != 0)
		{
			lSize = numBytes;
		}
		if (offset != 0)
		{
			nc_args->message += offset;
			if (numBytes == 0)
				lSize -= offset;
		}

		//Read the file in blocks and send it to server
		memset(buffer, '\0', sizeof(buffer) + 1);
		while (lSize > 0){

			memset(block, '\0', sizeof(block) + 1);
			strncpy(block, nc_args->message, sizeof(block));
			nc_args->message += sizeof(block);
			
			lSize -= sizeof(block);
			if (lSize < 0){
				memset(block + (sizeof(block) + lSize), '\0', ((-1)*(lSize)) + 1);
				// Send the block to the server
				numBytes = write(sock, block, strlen(block));
				if (nc_args->verbose == 1)
					printf("Packet sent!!!\n");
				if (numBytes < 0)
					DieWithSystemMessage("send() failed");
				else if (numBytes != strlen(block))
					DieWithUserMessage("send()", "sent unexpected number of bytes");

				//append the block to buffer
				strcat(buffer, block);
				break;
			}

			// Send the block to the server
			numBytes = write(sock, block, strlen(block));
			if (nc_args->verbose == 1)
				printf("Packet sent!!!\n");
			if (numBytes < 0)
				DieWithSystemMessage("send() failed");
			else if (numBytes != strlen(block))
				DieWithUserMessage("send()", "sent unexpected number of bytes");

			//append the block to buffer
			strcat(buffer, block);
		}

	}
	else
	{
		fp = fopen(filename, "rb");
		if (fp == NULL) {
			fputs("Failed to open input file\n", stderr);
			exit(1);
		}

		// obtain file size:
		fseek(fp, 0, SEEK_END);
		lSize = ftell(fp);
		rewind(fp);

		if (lSize == 0)
		{
			printf("No text in file to send... \n");
			exit(1);
		}



		if (numBytes != 0)
		{
			lSize = numBytes;
		}
		if (offset != 0)
		{
			fseek(fp, offset, SEEK_SET);
			if (numBytes == 0)
				lSize -= offset;
		}
		
		//Read the file in blocks and send it to server
		memset(buffer, '\0', sizeof(buffer) + 1);
		while (!feof(fp)){
			
			memset(block, '\0', sizeof(block)+1);
			result = fread(block, 1, sizeof(block), fp);
			if (ferror(fp)) {
				fputs("Unable to read the input file\n", stderr);
				exit(3);
			}

			lSize -= sizeof(block);
			if (lSize < 0){
				memset(block + (sizeof(block) + lSize), '\0', ((-1)*(lSize))+1);
				// Send the block to server
				numBytes = write(sock, block, strlen(block));
				if (nc_args->verbose == 1)
					printf("Packet sent!!!\n");
				if (numBytes < 0)
					DieWithSystemMessage("send() failed");
				else if (numBytes != strlen(block))
					DieWithUserMessage("send()", "sent unexpected number of bytes");

				//append the block to buffer
				strcat(buffer, block);
				break;
			}

			// Send the block to server
			numBytes = write(sock, block, strlen(block));
			if (nc_args->verbose == 1)
				printf("Packet sent!!!\n");
			if (numBytes < 0)
				DieWithSystemMessage("send() failed");
			else if (numBytes != strlen(block))
				DieWithUserMessage("send()", "sent unexpected number of bytes");

			//append the block to buffer
			strcat(buffer, block);
		}
		fclose(fp);
	}

	// Calculate the digest using HMAC
	unsigned char *hash;
	int hashlen;
	char hashlenstr[2];

	hash = HMAC(EVP_sha1(), key, keylen, buffer, strlen(buffer), NULL, &hashlen);
	sprintf(hashlenstr, "%d", hashlen);
	strcat(hash, hashlenstr);
	

	// Send the digest to  server
	numBytes = write(sock, hash, strlen(hash));
	if (nc_args->verbose == 1)
		printf("Packet sent!!!\n");
	if (numBytes < 0)
		DieWithSystemMessage("send() failed");
	else if (numBytes != strlen(hash))
		DieWithUserMessage("send()", "sent unexpected number of bytes");

	close(sock);
}

void launchServer(nc_args_t *nc_args)
{

		FILE *fp;
		char buffer[BUFSIZE];
		char block[100];
		ssize_t numBytesRcvd;

		// Create socket for incoming connections
		int servSock; // Socket descriptor for server
		if ((servSock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0)
			DieWithSystemMessage("socket() failed");

		// Bind to the local address
		if (bind(servSock, (struct sockaddr*) &nc_args->destaddr, sizeof(nc_args->destaddr)) < 0)
			DieWithSystemMessage("bind() failed");

		// Mark the socket so it will listen for incoming connections
		if (listen(servSock, MAXPENDING) < 0)
			DieWithSystemMessage("listen() failed");

		for (;;) { // Run forever

			struct sockaddr_in clntAddr; // Client address
			// Set length of client address structure (in-out parameter)
			socklen_t clntAddrLen = sizeof(clntAddr);

			// Wait for a client to connect
			int clntSocket = 0;
			clntSocket = accept(servSock, (struct sockaddr *) &clntAddr, &clntAddrLen);
			if (clntSocket < 0)
				DieWithSystemMessage("accept() failed");
			if (nc_args->verbose == 1)
				printf("Connected to client...\n");

			// clntSock is connected to a client!
			char clntName[INET_ADDRSTRLEN]; // String to contain client address
			if (inet_ntop(AF_INET, &clntAddr.sin_addr.s_addr, clntName,
				sizeof(clntName)) != NULL)
				printf("Handling client %s/%d\n", clntName, ntohs(clntAddr.sin_port));
			else
				puts("Unable to get client address");

			if (nc_args->verbose == 1)
				printf("Receiving packets...\n");

			// Receive message from client
			memset(block, '\0', sizeof(block) + 1);
			numBytesRcvd = read(clntSocket, block, sizeof(block));
			if (numBytesRcvd < 0)
				DieWithSystemMessage("read() failed");

			// Receive again until end of stream
			memset(buffer, '\0', sizeof(buffer) + 1);
			while (numBytesRcvd > 0) {
				// 0 indicates end of stream
				// See if there is more data to receive
				strcat(buffer, block);

				memset(block, '\0', sizeof(block) + 1);
				numBytesRcvd = read(clntSocket, block, sizeof(block));
				if (nc_args->verbose == 1)
					printf("Packet received!!!\n");
				if (numBytesRcvd < 0)
					DieWithSystemMessage("read() failed");
			}

			// Calculate the digest using HMAC
			unsigned char *hash;
			int hashlen;
			int newhashlen;
			char recvhash[100];
			char hashlenstr[2];

			memset(hashlenstr, '\0', sizeof(hashlenstr) + 1);
			memmove(hashlenstr, buffer + (strlen(buffer) - 2), 2);
			puts(hashlenstr);
			hashlen = atoi(hashlenstr);

			memset(recvhash, '\0', sizeof(recvhash) + 1);
			memmove(recvhash, buffer + (strlen(buffer) - 2 - hashlen), hashlen);
			

			memset(buffer + (strlen(buffer) - 2 - hashlen), '\0', sizeof(buffer) - (strlen(buffer) - 2 - hashlen) + 1);
			puts(buffer);

			hash = HMAC(EVP_sha1(), key, keylen, buffer, strlen(buffer), NULL, &newhashlen);
			memset(hash + newhashlen, '\0', 100 - newhashlen + 1);
			

			if (memcmp(recvhash, hash, hashlen) == 0){
				if (nc_args->verbose == 1)
					printf("Writing to file...\n");
				fp = fopen(nc_args->filename, "w");
				fwrite(buffer, sizeof(char), strlen(buffer), (FILE *)fp);
				if (nc_args->verbose == 1)
					printf("File is ready!!!\n");
				fclose(fp);
			}

			close(clntSocket);

		} 
	
	
}

	void DieWithUserMessage(const char *msg, const char *detail) {
		fputs(msg, stderr);
		fputs(": ", stderr);
		fputs(detail, stderr);
		fputc('\n', stderr);
		exit(1);
	}

	void DieWithSystemMessage(const char *msg) {
		perror(msg);
		exit(1);
	}



 

