#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
 
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>

#include <openssl/hmac.h> // need to add -lssl to compile

#define BUF_LEN 1024

/** Warning: This is a very weak supplied shared key...as a result it is not
 * really something you'd ever want to use again :)
 */
static const char key[16] = { 0xfa, 0xe2, 0x01, 0xd3, 0xba, 0xa9,
0x9b, 0x28, 0x72, 0x61, 0x5c, 0xcc, 0x3f, 0x28, 0x17, 0x0e };

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
  return;
}


int main(int argc, char * argv[]){
  nc_args_t nc_args;
  int sockfd;
  char input[BUF_LEN];

  //initializes the arguments struct for your use
  parse_args(&nc_args, argc, argv);


  /**
   * FILL ME IN
   **/

  return 0;
}
