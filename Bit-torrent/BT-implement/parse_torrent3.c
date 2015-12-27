#include<stdio.h>
#include<string.h>
#include<stdlib.h>

//output structure: 
typedef struct {
	char name[100]; //name of file
	int piece_length; //number of bytes in each piece
	int length; //length of the file in bytes
	int num_pieces; //number of pieces, computed based on above two values
	char * piece_hashes; //pointer to 20 byte data buffers containing the sha1sum of each of the pieces
} bt_info_t;

void parse_dic();
void parse_list();
int get_len(char ch);
void parse_str(int length);
void parse_int();
void populate_info(char *str, int nbr);


char len_str[50] ;
char value_str[50];
char str_name[100];
int length, value;
//int flag = 0;
char ch;
FILE *fp; 
int info_flag = 0;
int key_found = 0; // this flag is set whenever a key is encountered and reset after the value is parsed. 
char key[100];
bt_info_t info;
void main()
{
	//memset(torr_info, '\0', sizeof(torr_info)+1);
	fp = fopen("moby_dick.txt.torrent", "r");
	while ((ch = fgetc(fp)) != EOF)
	{
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
	
	printf("\nInfo structure:\n");
	printf("File name:\t%s\n", info.name);
	printf("File size (KB):\t%d\n", info.length);
	printf("piece length:\t%d\n", info.piece_length);
	printf("number of pieces:\t%d\n", info.num_pieces);
	printf("hash values for pieces:\t%s\n", info.piece_hashes);
}

void parse_dic()
{
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

void parse_list(){
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

int get_len(char ch)
{
	len_str[0] = '\0';
	strcat(len_str, &ch);
	while ((ch = fgetc(fp)) != ':')
	{
		strcat(len_str, &ch);
		
	}
	puts(len_str);
	length = atoi(len_str);
	return length;
}

void parse_str(int length)
{
	memset(str_name, '\0', sizeof(str_name)+1);
	fread(str_name,1,length,fp);
	puts(str_name);
		
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


void parse_int()
{
	value_str[0] = '\0';
	while ((ch = fgetc(fp)) != 'e')
	{
		strcat(value_str, &ch);
	}
	value = atoi(value_str);
	printf("value:%d\n",value);
		
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
			memcpy(info.name, str, strlen(str)+1);
			//info.name = str;
			return;
		}
		if(strcmp(key,"piece length") == 0 && nbr != 0) {
			info.piece_length = nbr;
			return;
		}
		if(strcmp(key,"pieces") == 0 && str[0] != '\0')
		{
				info.piece_hashes = str;
				info.num_pieces = strlen(info.piece_hashes)/20;
				return;
		}
}
