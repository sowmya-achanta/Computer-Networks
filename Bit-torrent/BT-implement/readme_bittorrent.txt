P538 - Computer Networks													10/19/14
Project2:  BitTorrent Client Implementation
By:           Jagadeesh Madagundi (jmadagun)	
                 Om Sowmya Harshini Achanta (omachant)
                 Shruthi Katapally (shrukata)
Description: 
In this project we are demonstrating the BitTorrentClient implementation function with 1 seeder and N leecher. We implemented additional peers concept using pthreads and have maintained data coherency using the mutex locks.

At first we parse the torrent file:
In this phase the torrent file is parsed and the required information regarding the file to be downloaded is extracted. The extracted information is placed into a structure which will be used further. 
We have Seeder and Client as two integral parts of the project:

The Seeder will do the following:  
1)Seeder opens a socket to listen and will bind to the system’s ip address in which it is running and will select a random port number.
2)On receiving a connection we will start a thread to connect to leecher and it will perform the following steps in order to establish the data transfer procedure. Seeder can connect to maximum of 5 incoming connections simultaneously. So even after connecting to one leecher, it listens continuously.
It will do the handshake which has the comparing of the initially received data from client ( 19Bittorrent Protocol,8 zero bytes for future use, info_hash, peer_id).
If the values are matched then it responds to the leecher with a handshake giving the bitfield. Else, it will leave the connection.
3)Seeder will send the piece depending upon the leecher’s response of requested data. Leecher will send interested message before requesting data as response to seeders handshake. 

The leecher will do the following:
1)Leecher opens a socket and will connect to the seeder’s ip address/port.
2)Leecher first starts the handshake where it gives the data –
19Bittorrent Protocol, 8 zero bytes for future use, info_hash, peer_id. 
3)Leecher will compare the peer id which server has sent in return for the response of leecher’s handshake message. If it matches, It then takes the bit field sent by the server and checks with its bitfield to find if it needs any data.
4)Seeder now sends the pieces which leecher requested and upon receiving, leecher will check for the hash of the piece and will save if hash matches.

We implemented logger to log the important events and messages .

Compilation: 
In order to compile without the make me file, 
gcc bt_client.c bt_lib.c bt_setup.c –lssl -lpthread 
In order to compile using makefile,
1) make clean : This removes the previously generated object files if exists. 
2) Make : This command compiles the .c files and gives the necessary object file. 
Files present: bt_client.c,bt_setup.c,bt_lib.c,bt_lib.h,bt_setup.h,   

Execution:
For program to run as seeder, We give :
./bt_client –v [-p client1_ipaddress:port –p client2_ipaddress:port… -p client5_ipaddress:port] torrent_filename

For program to run as leecher, We give :

./bt.client –s save_filename –p seeder_ip:port –I leecher_port torrent_filename
		
Options which we can give are:
1)	-h option: For help screen.
2)	–s option: For saving the output file.
3)	–l option: For saving the logs of the happenings in seeder and leecher side.
4)	–p option: For contacting the specific peer.
5)	–I option: To give a specific port number to the leecher. 
6)	–v option: To run the server.	
			


Output Analyzation:
                                We have output files which were saved by leechers.
                                We have a file “bt_client.log” where we can check the logged data. It has the entire data where there was a logging happening in the program for messages and events.
                                          
