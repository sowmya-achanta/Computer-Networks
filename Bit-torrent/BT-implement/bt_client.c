#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <netinet/in.h>
#include <netinet/ip.h> //ip hdeader library (must come before ip_icmp.h)
#include <netinet/ip_icmp.h> //icmp header
#include <arpa/inet.h> //internet address library
#include <netdb.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <signal.h>

#include <net/if.h>
#include <sys/ioctl.h>

#include <pthread.h>

#include "bt_lib.h"
#include "bt_setup.h"

#define MAXPENDING 5
#define BLOCK_SIZE 16

void launchClient(void * args);
void launchServer(bt_args_t * bt_args);
void handleClient(void * args);
void parse_torrent(char * torrent_file);
void parse_dic();
void parse_list();
int get_len(char ch);
void parse_str(int length);
void parse_int();
void populate_info(char *str, int nbr);
void initialise();
void DieWithUserMessage(const char *msg, const char *detail);
void DieWithSystemMessage(const char *msg);

FILE *fp;
char ch;
bt_info_t info;
int info_flag = 0;
int key_found = 0; // this flag is set whenever a key is encountered and reset after the value is parsed. 
char key[100];
char len_str[50] ;
char value_str[50];
char str_name[100];
int length, value;
char info_value[1024];
int info_len;
char info_hash[20];
pthread_mutex_t lock;
int peer_found=0;

int main (int argc, char * argv[]) {

	bt_args_t bt_args;
	int i;
	pthread_t bt_thread[5];

	parse_args(&bt_args, argc, argv);

	if(bt_args.verbose){
		printf("Args:\n");
		printf("verbose: %d\n",bt_args.verbose);
		printf("save_file: %s\n",bt_args.save_file);
		printf("log_file: %s\n",bt_args.log_file);
		printf("torrent_file: %s\n", bt_args.torrent_file);

		for(i=0;i<MAX_CONNECTIONS;i++){
			if(bt_args.peers[i] != NULL)
				print_peer(bt_args.peers[i]);
		}
	}
	//read and parse the torrent file here

	if(bt_args.verbose){
		// print out the torrent file arguments here
	}
	  
	// Parse Torrent File
	parse_torrent(bt_args.torrent_file);
	 
	// Perform any initialisation steps required
	initialise();
	  
	if (bt_args.verbose)
		launchServer(&bt_args);
	else {
		// start mutex
		pthread_mutex_init(&lock, NULL);
		// launch a client thread for each peer
		for(i=1;bt_args.peers[i] != NULL;i++) {
			printf("thread %d launched with return value %d\n" , i, pthread_create(&bt_thread[i-1], NULL, (void *)launchClient, &bt_args));
		}
		// end mutex
		pthread_mutex_destroy(&lock); 
		
		// wait till all the threads finish execution		
		for(i=1;bt_args.peers[i] != NULL;i++) {
			pthread_join(bt_thread[i-1], NULL);
		}
	}
	
	return 0;
}

void initialise() {
	int i, have_pieces[info.num_pieces];
	for(i=0;i<info.num_pieces;i++) {
		have_pieces[i]=0;
	}
	//update_have(have_pieces);
	return;
}

void launchClient(void * args) {
	bt_args_t * bt_args = (bt_args_t *) args;
	
	//char buffer[BUFSIZE];
	char block[100];
	char recv_block[100];
	int numBytes;
	
	SHA1((unsigned char *) info_value, info_len, (unsigned char *) info_hash);
	
	// Create a reliable, stream socket using TCP
	int sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sock < 0)
		DieWithSystemMessage("socket() failed");
	
	puts("reached");
	peer_t *peer = bt_args->peers[1];
	puts("reached");
	
	// Establish  connection to the  server
	if (connect(sock, (struct sockaddr *) &peer->sockaddr, sizeof(peer->sockaddr)) < 0)
		DieWithSystemMessage("connect() failed");

 	//Read the file in blocks and send it to server
	memset(block,'\0',sizeof(block)+1);
	strcat(block,"19BitTorrent Protocol00000000");
	strcat(block, info_hash);
	
 	peer_t self;
	self.port = bt_args->id; //the port to connect n
	self.interested = 1;
	
	int fd;
    struct ifreq ifr;
    char iface[] = "eth0";
    fd = socket(AF_INET, SOCK_DGRAM, 0);
	//Type of address to retrieve - IPv4 IP address
    ifr.ifr_addr.sa_family = AF_INET;
	//Copy the interface name in the ifreq structure
    strncpy(ifr.ifr_name , iface , IFNAMSIZ-1);
	ioctl(fd, SIOCGIFADDR, &ifr);
	close(fd);
    //display result
    char * self_ip = inet_ntoa(( (struct sockaddr_in *)&ifr.ifr_addr )->sin_addr) ;
	puts(self_ip);
	
	calc_id(self_ip,self.port,self.id);
	puts(self.id);
	
	strcat(block, self.id);
	
	// Send the block to server
	numBytes = write(sock, block, strlen(block));
	if (numBytes < 0)
		DieWithSystemMessage("send() failed");
	else if (numBytes != strlen(block))
		DieWithUserMessage("send()", "sent unexpected number of bytes"); 
	
/* 	// Receive handshake message from seeder
	memset(recv_block, '\0', sizeof(recv_block) + 1);
	numBytes = read(sock, recv_block, sizeof(recv_block));
	if (numBytes < 0)
		DieWithSystemMessage("read() failed");
	 */
/* 	if(memcmp(recv_block,block,strlen(recv_block))!=0){
			close(sock);
			puts("invalid handshake msg");
			return;
		}
		 */
	puts("success");
	
	FILE *dfp;
	char temp[100],bt_msg_len_str[100],bt_type_str[1],bt_piece_index[100],bt_piece_begin[100];
	bt_piece_t * piece;
	bt_msg_t bt_msg;
	bt_msg_t * msg;
	int offset,i;
	int num_msgs = 0;
	dfp = fopen(bt_args->save_file,"wb+x");
	if(dfp!=NULL)
		fclose(dfp);
	//extracting information from the message sent after handshake success
	memset(recv_block, '\0', sizeof(recv_block) + 1);
	msg = (bt_msg_t *) malloc(32);
	numBytes = read(sock, recv_block, 32);
	num_msgs++;
	if (numBytes < 0)
		DieWithSystemMessage("read() failed");
	
	while(numBytes>0) {
		memcpy(msg,recv_block,32);
		//printf("num of bytes recv %d\n",numBytes);
		//printf("msg:\n length: %d\n type: %d\n" , msg->length, msg->bt_type);
		//printf("index: %d\n begin: %d\n", msg->payload.piece.index,msg->payload.piece.begin);
		msg->payload.piece.piece[msg->length - 20]='\0';
		//puts(msg->payload.piece.piece);
		switch(msg->bt_type) {
			  case 0: break; // choke 
			  case 1: break; // unchoke
			  case 2: break; // interested
			  case 3: break; // not interested
			  case 4: break; // have
			  case 5: break; // bitfield
			  case 6: break; // request
			  case 7: 
				dfp = fopen(bt_args->save_file,"rb+");
				//calculate offset into file where data has to be inserted.
				offset = (msg->payload.piece.index * info.piece_length) + msg->payload.piece.begin;
				fseek(dfp,offset,SEEK_SET);
				
				//memcpy(msg->payload.piece.piece,recv_block+8,16);
				//puts(msg->payload.piece.piece);
				fputs(msg->payload.piece.piece,dfp);
				//fwrite(msg->payload.piece.piece,1,BLOCK_SIZE,dfp);
				/* for(i=0;i < msg->length - 6;i++) {
					fputc(msg->payload.piece.piece+i,dfp); 
					//putc(msg->payload.piece.piece+i,stdout); 
				} */
				fclose(dfp);
				break;
			  case 8: break; // keep-alive
		} 
		
		// continue extracting information from the message sent after handshake success
		memset(recv_block, '\0', sizeof(recv_block) + 1);
		numBytes = read(sock, recv_block, 32);
		num_msgs++;
		if (numBytes < 0)
			DieWithSystemMessage("read() failed");
		}
		printf("%d\n",num_msgs);
		close(sock);
}

void launchServer(bt_args_t * bt_args) {

	char block[100];
	ssize_t numBytesRcvd;
	int i,tid=0;
	pthread_t bt_thread[5];
		
	SHA1((unsigned char *) info_value, info_len, (unsigned char *) info_hash);
		
	// Create socket for incoming connections
	int servSock; // Socket descriptor for server
	if ((servSock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0)
		DieWithSystemMessage("socket() failed");

	// Bind to the local address
	// Construct local address structure
	struct sockaddr_in servAddr; // Local address
	memset(&servAddr, 0, sizeof(servAddr)); // Zero out structure
	servAddr.sin_family = AF_INET; // IPv4 address family
	servAddr.sin_addr.s_addr = htonl(INADDR_ANY); // Any incoming interface
	servAddr.sin_port = 0; // random port

	if (bind(servSock, (struct sockaddr*) &servAddr, sizeof(servAddr)) < 0)
		DieWithSystemMessage("bind() failed");

	// Mark the socket so it will listen for incoming connections
	if (listen(servSock, MAXPENDING) < 0)
		DieWithSystemMessage("listen() failed");

	struct sockaddr_in sin;
	socklen_t len = sizeof(sin);
	getsockname(servSock, (struct sockaddr *)&sin, &len);
    printf("port number %d\n", ntohs(sin.sin_port));
	
	for (;;) { // Run forever

		struct sockaddr_in clntAddr; // Client address
		// Set length of client address structure (in-out parameter)
		socklen_t clntAddrLen = sizeof(clntAddr);
		
		puts("waiting for client request\n");
		// Wait for a client to connect
		int clntSocket = 0;
		clntSocket = accept(servSock, (struct sockaddr *) &clntAddr, &clntAddrLen);
		if (clntSocket < 0)
			DieWithSystemMessage("accept() failed");

		bt_args->sockets[tid] = clntSocket;
		printf("client socket = %d\n",clntSocket);
		bt_args->id = tid;
			
		// launch thread from here
		// start mutex
		pthread_mutex_init(&lock, NULL);
		// launch a handle_client thread for each peer
		printf("thread %d launched with return value %d\n" , tid, pthread_create(&bt_thread[tid++], NULL, (void *)handleClient, bt_args));
		
		// end mutex
		pthread_mutex_destroy(&lock); 
		
		//close(servSock);
		//return;
	} 
}

void handleClient(void * args){
	bt_args_t * bt_args = (bt_args_t *) args;
	
	char block[100];
	ssize_t numBytesRcvd;
	int i;
	
	struct sockaddr_in clntAddr; // Client address
	// Set length of client address structure (in-out parameter)
	socklen_t clntAddrLen = sizeof(clntAddr);
	
	// Wait for a client to connect
	int clntSocket = bt_args->sockets[bt_args->id];	
	printf("bt args id = %d\n",bt_args->id);
	printf("client socket = %d\n",clntSocket);
	
	getsockname(clntSocket, (struct sockaddr *) &clntAddr, (socklen_t *)&clntAddrLen);
	
	// clntSock is connected to a client!
	char clntName[INET_ADDRSTRLEN]; // String to contain client address
	if (inet_ntop(AF_INET, &clntAddr.sin_addr.s_addr, clntName,	sizeof(clntName)) != NULL)
		printf("Handling client %s/%d\n", clntName, ntohs(clntAddr.sin_port));
	else
		puts("Unable to get client address");

	// Receive message from client
	memset(block, '\0', sizeof(block) + 1);
	numBytesRcvd = read(clntSocket, block, sizeof(block));
	if (numBytesRcvd < 0)
		DieWithSystemMessage("read() failed");
	
	//puts(block);
	char recv_info_hash[20]; 
	strncpy(recv_info_hash, block+29, sizeof(recv_info_hash));
	puts(recv_info_hash);
	puts(info_hash);
	
	if(memcmp(recv_info_hash,info_hash,20)!=0){
		close(clntSocket);
		puts("info mismatch");
		return;
	}
	char recv_peer_id[20];
	strncpy(recv_peer_id, block+49, sizeof(recv_peer_id));
	puts(recv_peer_id);
	for(i=1; bt_args->peers[i]!=NULL;i++) {
		peer_t *peer = bt_args->peers[i];
		puts(peer->id);
		if(memcmp(recv_peer_id,peer -> id,20)==0){
			peer_found = 1;
			break;
		}
	}
	if(peer_found!=1) {
		close(clntSocket);
		puts("peer id mismatch");
		return;
	} 
	puts("success");
	
	//numBytesRcvd = write(clntSocket, block, strlen(block));
/* 		if (numBytesRcvd < 0)
		DieWithSystemMessage("send() failed");
	else if (numBytesRcvd != strlen(block))
		DieWithUserMessage("send()", "sent unexpected number of bytes");
*/
	// Send bitfield msg
	
	// Send bt_msg
	FILE *dfp;
	char temp[BLOCK_SIZE];
	//bt_msg_t bt_msg;
	bt_msg_t * bt_msg = (bt_msg_t *) malloc(24);
	bt_piece_t * piece;
/* 		bt_msg.bt_type = 7;
	bt_msg.payload.piece.index = 2;
	bt_msg.payload.piece.begin = 16;
	strncpy(bt_msg.payload.piece.piece,temp,strlen(temp));
	bt_msg.length = sizeof(bt_msg.bt_type) + sizeof(bt_msg.payload); */
	//msg = &bt_msg;
/* 		printf("size of bt_msg %d\n" , sizeof(bt_msg));
	numBytesRcvd = write(clntSocket, msg, sizeof(bt_msg));
	if (numBytesRcvd < 0)
		DieWithSystemMessage("send() failed");
	else if (numBytesRcvd != sizeof(bt_msg))
		DieWithUserMessage("send()", "sent unexpected number of bytes");
	 */
	dfp = fopen(info.name,"rb");
	//calculate offset into file where data has to be inserted.
	char a;
	char b[] = "cs";
	int num_msgs = 0;
	memset(temp,'\0',sizeof(temp)+1);
	for(i=0; (a = fgetc(dfp))!=EOF;i++) {
/* 		for(i=0; i < 16;i++) {
		a = fgetc(dfp); */
		strncpy(temp+(i%BLOCK_SIZE), &a, 1);
		if((i % BLOCK_SIZE) == (BLOCK_SIZE - 1)) {
			piece = &bt_msg->payload.piece;
			strncpy(piece->piece,temp,BLOCK_SIZE);
			piece->piece[BLOCK_SIZE]='\0';
			//puts(temp);
			//puts(piece->piece);
			//puts(bt_msg->payload.piece.piece);
			memset(temp,'\0',sizeof(temp)+1);
			bt_msg->bt_type = 7;
			bt_msg->payload.piece.index = i/info.piece_length;
			bt_msg->payload.piece.begin = (i % info.piece_length) - (BLOCK_SIZE - 1);
			bt_msg->length = sizeof(bt_msg->bt_type) + sizeof(bt_msg->payload) + BLOCK_SIZE;
			//printf("size of bt_type: %d\nsize of payload: %d\n",sizeof(bt_msg->bt_type) , sizeof(bt_msg->payload));
			//printf("size of index: %d\nsize of begin: %d\nsize of piece: %d\n",sizeof(bt_msg->payload.piece.index) , sizeof(bt_msg->payload.piece.begin),sizeof(bt_msg->payload.piece.piece));
			//msg = &bt_msg;
			numBytesRcvd = write(clntSocket, bt_msg, sizeof(bt_msg)+BLOCK_SIZE+8);
			num_msgs++;
			if (numBytesRcvd < 0)
				DieWithSystemMessage("send() failed");
			else if (numBytesRcvd != sizeof(bt_msg)+BLOCK_SIZE+8)
				DieWithUserMessage("send()", "sent unexpected number of bytes");
			//printf("num of bytes sent: %d\n",numBytesRcvd);
		}
	}
	if((i % BLOCK_SIZE) != (BLOCK_SIZE - 1)) {
		piece = &bt_msg->payload.piece;
		strncpy(piece->piece,temp,(i % BLOCK_SIZE) + 1);
		piece->piece[BLOCK_SIZE]='\0';
		//puts(bt_msg->payload.piece.piece);
		memset(temp,'\0',sizeof(temp)+1);
		bt_msg->bt_type = 7;
		bt_msg->payload.piece.index = i/info.piece_length;
		bt_msg->payload.piece.begin = (i % info.piece_length) - (i % BLOCK_SIZE);
		bt_msg->length = sizeof(bt_msg->bt_type) + sizeof(bt_msg->payload) + (i % BLOCK_SIZE);
		//msg = &bt_msg;
		numBytesRcvd = write(clntSocket, bt_msg, sizeof(bt_msg)+(i % BLOCK_SIZE)+8);
		num_msgs++;
		if (numBytesRcvd < 0)
			DieWithSystemMessage("send() failed");
		else if (numBytesRcvd != sizeof(bt_msg)+(i % BLOCK_SIZE)+8)
			DieWithUserMessage("send()", "sent unexpected number of bytes");
		//printf("num of bytes sent: %d\n",numBytesRcvd);
	}
	printf("%d\n",num_msgs);
	fclose(dfp);
	
	close(clntSocket);
	peer_found = 0;
	pthread_exit(NULL);
}

void parse_torrent(char * torrent_file) {

	fp = fopen(torrent_file, "rb");
	
	// obtain file size:
	fseek (fp , 0 , SEEK_END);
	long lSize = ftell (fp);
	rewind (fp);
	
	// allocate memory to contain the whole file:
	char * buffer = (char*) malloc (sizeof(char)*lSize);
	if (buffer == NULL) {fputs ("Memory error",stderr); exit (2);}
	
	// copy the file into the buffer:
	size_t result = fread (buffer,1,lSize,fp);
	char * temp;
	temp = strstr(buffer,"4:info");
	temp += 6;
	int str_len = strlen(temp);
	temp[str_len - 1] = '\0';
	strncpy(info_value, temp, strlen(temp));
	info_len = strlen(info_value);
	//puts(info_value);
	rewind(fp);
		
	while ((ch = fgetc(fp)) != EOF)	{
		switch (ch){

		case 'd':
			parse_dic();
			break;
		case 'i':
			parse_int();
			break;
		case 'l':
			parse_list();
			break;
		case '0' ... '9':
			get_len(ch);
			parse_str(length);
			break;
		default:
			fprintf(stderr, "ERROR: Unknown option '-%c'\n", ch);
			exit(1);

		}
	}
	printf("File name:\t%s\n", info.name);
/* 	printf("\nInfo structure:\n");
	
	printf("File size (KB):\t%d\n", info.length);
	printf("piece length:\t%d\n", info.piece_length);
	printf("number of pieces:\t%d\n", info.num_pieces);
	printf("hash values for pieces:\t%s\n", info.piece_hashes);
 */	
	fclose(fp);
	free(buffer);
}

void parse_dic() {
	//puts(&ch);
	while ((ch = fgetc(fp)) != 'e')
	{
		switch (ch){
		case 'd':
			parse_dic();
			break;
		case 'l':
			parse_list();
			break;
		case 'i':
			//puts(&ch);
			parse_int();
			break;
		case '0' ... '9':
			get_len(ch);
			parse_str(length);
			break;
		default:
			fprintf(stderr, "ERROR: Unknown option '-%c'\n", ch);
			exit(1);
		}
	}
}

void parse_list() {
	//puts(&ch);
	while ((ch = fgetc(fp)) != 'e')
	{
		switch (ch){
		case 'd':
			parse_dic();
			break;
		case 'l':
			parse_list();
			break;
		case 'i':
			//puts(&ch);
			parse_int();
			break;
		case '0' ... '9':
			get_len(ch);
			parse_str(length);
			break;
		default:
			fprintf(stderr, "ERROR: Unknown option '-%c'\n", ch);
			exit(1);
		}
	}
}

int get_len(char ch) {
	len_str[0] = '\0';
	strcat(len_str, &ch);
	while ((ch = fgetc(fp)) != ':')
	{
		strcat(len_str, &ch);
	}
	//puts(len_str);
	length = atoi(len_str);
	return length;
}

void parse_str(int length) {
	memset(str_name, '\0', sizeof(str_name)+1);
	fread(str_name,1,length,fp);
	//puts(str_name);
		
	if (strcmp(str_name, "announce") == 0 
		|| strcmp(str_name, "length") == 0 
		|| strcmp(str_name, "name") == 0 
		|| strcmp(str_name, "piece length") == 0 
		|| strcmp(str_name, "pieces") == 0)
	{

		memset(key, '\0', sizeof(key)+1);
		memcpy(key, str_name, strlen(str_name) + 1);
		//key = str_name;
		key_found = 1;
		return;
	}
	
	if (key_found == 1) {
		populate_info(str_name,0);
		key_found = 0;
	}
}

void parse_int() {
	value_str[0] = '\0';
	while ((ch = fgetc(fp)) != 'e')
	{
		strcat(value_str, &ch);
	}
	value = atoi(value_str);
	//printf("value:%d\n",value);
		
	if (key_found == 1) {
		populate_info("\0",value);
		key_found = 0;
	}
}

void populate_info( char *str, int nbr ) {
	
		if(strcmp(key,"length")==0 && nbr != 0) {
			info.length = nbr;
			return;
		}
		if(strcmp(key,"name") == 0 && str[0] != '\0') {
			strncpy(info.name, str, strlen(str)+1);
			//info.name = str;
			return;
		}
		if(strcmp(key,"piece length") == 0 && nbr != 0) {
			info.piece_length = nbr;
			return;
		}
		if(strcmp(key,"pieces") == 0 && str[0] != '\0')
		{
			int i;
			info.num_pieces = strlen(str)/20;
			info.piece_hashes = str;
/* 			for ( i = 0; i < info.num_pieces; i++) {
				*(info.piece_hashes+(i*20)) = str+(i*20);
				puts("reached");
			} */
			return;
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

