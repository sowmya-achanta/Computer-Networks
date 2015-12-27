Name: Jagadeesh Madagundi

Username: jmadagun

Name: Sowmya Achanta

Username: omachant

Assignment: Wiretap

------------------------------------------------------------------------------------------------------------------

Credits:

http://www.cplusplus.com

tcpdump.org

stackoverflow.com

Lab manual and project description provided.

----------------------------------------------------------------------------------------------------------------------

About wiretap.cpp:

This program reads each packet from a given pcap file, parses through them and displays selective information from it. This information is displayed using functions that handle the following headers in the packet:
 1. Ethernet header
-Extracts source and destination addresses
-Counts the total number of source and destination addresses of all the packets
 2. IP header
-Extracts the unique network layer protocols of all the packets
-Extracts the unique source and destination IPv4 addresses with respective counts for all packets(IPv6 ignored)
 3. ARP header
-Extracts the unique ARP participants, their respective MAC and IPv4 addresses and counts.
 4. TCP header
-Extracts unique source and destination ports for all packets along with their counts
-Extracts the TCP flags set with the count of each flag for all the packets 
-Extracts TCP options and displays the kind of options along with the number of times they've occurred all the packets.
Note: The count for TCP option NOP(kind =1) will be calculated by the number of times it occurs in each packet.
 5. UDP header
-Extracts unique source and destination ports for all packets along with their counts
 6. ICMP header
-Extracts unique ICMP types and codes for all packets along with their counts
 7. Packet summary
-Displays the total number of packets, start time and date, duration, average, minimum and maximum packet sizes 
 8. Options to the user:
--help-> displays instructions to run the program
--open-> to parse the pcap file 

Additionally, wt_lib.h is a header file that has structures to store values and  the aggregated counts for each of the above fields to be displayed.

Instructions to compile:

g++ -lpcap wiretap.cpp -o wiretap

Makefile has also been supplied using which the compilation is as follows:

make

Instructions to run:

./wiretap --open <filename>

Interpreting the output:

The information will be displayed on the standard output in a user friendly format.

The code works fine on burrow.soic.indiana.edu machines. 
