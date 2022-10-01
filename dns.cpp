/*
* Login: xkrajc21
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>

#include "dns.hpp"

/*
* Read one label of domain name. After all characters of label have been read, it puts dot in the end. 
*/
int read_label(char *namePtr, char *nameToPrint, char *buffer)
{
	char *temp = NULL;
	char numOfChars = *namePtr;

	if (strlen(nameToPrint) == 0)
	{
		strncpy(nameToPrint, (namePtr + 1), numOfChars); // +1 offset because first byte is number of characters in label
	}
	else
	{
		strncat(nameToPrint, (namePtr + 1), numOfChars); // +1 offset because first byte is number of characters in label
	}

	strcat(nameToPrint, ".");
	return numOfChars + DOT_SIZE;
}

/*
*	Reads whole domain name, with help of read_label() function. If it find pointer, recursively call itself and continue reading.
*/
int read_name(char *namePtr, char *nameToPrint, char *buffer)
{
	int totalRead = 0;

	while (*(namePtr + totalRead) != 0)
	{
		if ((htons((*(uint16_t *)(namePtr + totalRead))) & ((uint16_t) 0xC000)) == ((uint16_t) 0xC000))
		{
			read_name(buffer + (htons((*(uint16_t *)(namePtr + totalRead))) & 0x3fff), nameToPrint, buffer);
			totalRead += NAME_ADDRESS_SIZE;
			return totalRead;
		}
		totalRead += read_label(namePtr + totalRead, nameToPrint, buffer);
	}
	nameToPrint[strlen(nameToPrint)] = '\0';
	return totalRead + NULL_CHAR_SIZE;
}

/*
*	Gets pointer of start of the question section. Reads question domain name with help of read_name() function and then use structure "question"
*	to print out type and class.
*/
int decompose_query(char *namePtr, char *nameToPrint, char *buffer)
{
	unsigned int totalRead = 0;
	question *questionItems = (question *) namePtr;
	totalRead = read_name(namePtr, nameToPrint, buffer);
	questionItems = (question *) ((char *) namePtr + totalRead);
	printf(" %s, ", nameToPrint);
	switch (ntohs(questionItems->type))
	{
	case A:
		printf("A, ");
		break;
	case AAAA:
		printf("AAAA, ");
		break;
	case PTR:
		printf("PTR, ");
		break;
	default:
		printf("Unknown type");
		break;
	}
	
	switch (ntohs(questionItems->classNum))
	{
	case class_IN:
		printf("IN\n");
		break;
	}
	return totalRead + sizeof(question);
}

/*
*	Decomposes RDATA for RR (resource record) of type MX.
*/
int decompose_rdata_mx(char *rdata_start, char *nameToPrint, char *buffer)
{
	printf("preference: %d, ", *(uint16_t *) rdata_start);
	return (read_name( rdata_start + sizeof(uint16_t), nameToPrint, buffer) + sizeof(uint16_t));
}

/*
*	Decomposes RDATA for RR of type SOA. Uses read_name() function and structure "SOA_RDATA" to get all specific data.
*/
int decompose_rdata_soa(char *rdata_start, char *nameToPrint, char *buffer)
{	
	int totalRead = 0;
	SOA_rdata *SOAStruct = NULL;
	totalRead += read_name(rdata_start, nameToPrint, buffer);
	printf("%s, ", nameToPrint);
	memset(nameToPrint, 0, MAX_NAME_SIZE);

	totalRead += read_name(rdata_start + totalRead, nameToPrint, buffer);
	printf("%s, ", nameToPrint);
	memset(nameToPrint, 0, MAX_NAME_SIZE);
	SOAStruct = (SOA_rdata *) (rdata_start + totalRead);
	printf("serial: %d, ", ntohl(SOAStruct->serial));
	printf("%d, ", ntohl(SOAStruct->refresh));
	printf("%d, ", ntohl(SOAStruct->retry));
	printf("%d, ", ntohl(SOAStruct->expire));
	printf("%d\n", ntohl(SOAStruct->mininum));
	return (totalRead + sizeof(SOA_rdata));
}

/*
*	Gets pointer of start of the RR. Reads name, type, class and then depending ond type, calls another function to decompose RDATA.
*	NOTE: Not all types are fully supported, which mean that RDATA is not printed out. List of partialy supported types: NULL, WKS,
*	HINFO, MINFO, TXT.
*/
int decompose_RR(char *namePtr, char *nameToPrint, char *buffer)
{
	int totalRead = 0;
	RR *RRItems = NULL;
	if ((*namePtr == 0))
	{
		printf("<root>, ");
		totalRead += NULL_CHAR_SIZE;
	}
	else
	{
		totalRead = read_name(namePtr, nameToPrint, buffer);
		printf(" %s, ", nameToPrint);
	}
	memset(nameToPrint, 0, MAX_NAME_SIZE);
	RRItems = (RR *)  (namePtr + totalRead);

	switch (ntohs(RRItems->type))
	{
		type(A)
			inet_ntop(AF_INET, ((char *) RRItems) + sizeof(RR), nameToPrint, MAX_NAME_SIZE);
			totalRead += IPV4_BYTE_FORMAT_SIZE;
			break;
		type(NS)
			totalRead += read_name(((char *) RRItems + sizeof(RR)), nameToPrint, buffer);
			break;
		type(MD)
			totalRead += read_name(((char *) RRItems + sizeof(RR)), nameToPrint, buffer);
			break;
		type(MF)
			totalRead += read_name(((char *) RRItems + sizeof(RR)), nameToPrint, buffer);
			break;
		type(CNAME)
			totalRead += read_name(((char *) RRItems + sizeof(RR)), nameToPrint, buffer);
			break;
		type(SOA)
			break;
		type(MB)
			totalRead += read_name(((char *) RRItems + sizeof(RR)), nameToPrint, buffer);
			break;
		type(MG)
			totalRead += read_name(((char *) RRItems + sizeof(RR)), nameToPrint, buffer);
			break;
		type(MR)
			totalRead += read_name(((char *) RRItems + sizeof(RR)), nameToPrint, buffer);
			break;
		type(RR_NULL)
			sprintf( nameToPrint, "RDATA are not supported for this type");
			totalRead += ntohs(RRItems->dataLenght);
			break;
		type(WKS)
			sprintf( nameToPrint, "RDATA are not supported for this type");
			totalRead += ntohs(RRItems->dataLenght);
			break;
		type(PTR)
			totalRead += read_name(((char *) RRItems + sizeof(RR)), nameToPrint, buffer);
			break;
		type(HINFO)
			sprintf( nameToPrint, "RDATA are not supported for this type");
			totalRead += ntohs(RRItems->dataLenght);
			break;
		type(MINFO)
			sprintf( nameToPrint, "RDATA are not supported for this type");
			totalRead += ntohs(RRItems->dataLenght);
			break;
		type(MX)
			break;
		type(TXT)
			sprintf( nameToPrint, "RDATA are not supported for this type");
			totalRead += ntohs(RRItems->dataLenght);
			break;
		type(AAAA)
			inet_ntop(AF_INET6, ((char *) RRItems) + sizeof(RR), nameToPrint, MAX_NAME_SIZE);
			totalRead += IPV6_BYTE_FORMAT_SIZE;
			break;
		default:
			printf("Unknown type, ");
			totalRead += ntohs(RRItems->dataLenght);
			break;
	}
	switch (ntohs(RRItems->classNum))
	{
		case class_IN:
			printf("IN, ");
			break;
		case class_CS:
			printf("CS, ");
			break;
		case class_CH:
			printf("CH, ");
			break;
		case class_HS:
			printf("HS, ");
			break;
		default:
			printf("Unknown class");
			break;
	}
	printf("%d, ", ntohl(RRItems->TTL));
	if (ntohs(RRItems->type) == MX)
	{
		totalRead += decompose_rdata_mx(((char *) RRItems + sizeof(RR)), nameToPrint, buffer);
		printf("%s\n", nameToPrint);
	}
	else if (ntohs(RRItems->type) == SOA)
	{
		totalRead += decompose_rdata_soa(((char *) RRItems + sizeof(RR)), nameToPrint, buffer);
	}
	else
	{
		printf("%s\n", nameToPrint);
	}

	return totalRead + sizeof(RR);
}

/*
*	Prepares address for reverse transform by twisting whole adress and dividing every 4bits (IPv6) or byte with dot.
*/
int reverse_transform (char *address, char *reverseAddress)
{
	struct addrinfo hints;
	struct addrinfo *ipResult = NULL;
	bool ipv6 = true;
	char strTemp[13]; // max possible size of string inside

	memset (&hints, 0, sizeof (hints));
	hints.ai_family = AF_INET6;
	hints.ai_socktype = SOCK_DGRAM;
	if ((getaddrinfo(address, NULL, &hints, &ipResult)) != 0)
	{
		hints.ai_family = AF_INET;
		ipv6 = false;
		if ((getaddrinfo(address, NULL, &hints, &ipResult)) != 0)
		{
			fprintf(stderr, "Could not get any info about %s!\n", address);
			exit(1);
		}
	}

	if (ipv6)
	{
		for (int i = 15; i >= 0; i--)
		{
			sprintf(strTemp, "%01hx", (((unsigned char *) &((sockaddr_in6 *) ipResult->ai_addr)->sin6_addr)[i]) & 0x0f);
			strncat(reverseAddress, strTemp, 1);
			sprintf(strTemp, ".");
			strncat(reverseAddress, strTemp, 1);
			sprintf(strTemp, "%01hx", ((((unsigned char *) &((sockaddr_in6 *) ipResult->ai_addr)->sin6_addr)[i]) & 0xf0) >> 4);
			strncat(reverseAddress, strTemp, 1);
			sprintf(strTemp, ".");
			strncat(reverseAddress, strTemp, 1);
		}
		sprintf(strTemp, "ip6.arpa");
		strncat(reverseAddress, strTemp, 8);
		free(ipResult);
		return strlen(reverseAddress);
	}
	else
	{
		for (int i = 3; i >= 0; i--)
		{
			sprintf(strTemp, "%d", ((unsigned char *) &((sockaddr_in *) ipResult->ai_addr)->sin_addr)[i]);
			strcat(reverseAddress, strTemp);
			sprintf(strTemp, ".");
			strcat(reverseAddress, strTemp);
		}
		sprintf(strTemp, "in-addr.arpa");
		strncat(reverseAddress, strTemp, 12);
		free(ipResult);
		return strlen(reverseAddress);
	}
}

/*
*	Prepare domain name for sending as DNS question by writing number of characters in label, before every label in whole domain name.
*/
void string_transform(char * queryName, int addressSize)
{
	int numOfChars = 0;

	for (int actPos = 0; actPos < addressSize; ++actPos)
	{
		if (queryName[actPos] == '.')
		{
			numOfChars = 1;

			while ((queryName[actPos + numOfChars] != '.') && (queryName[actPos + numOfChars] != 0) && (actPos + numOfChars <= addressSize))
			{
				numOfChars++;
			}
			queryName[actPos] = numOfChars - 1;
		}
	}
}

/*
*	Searches for ip address of given server after parameter -s. If it's possible, it tries to get IPv6 address, rather then IPv4.
*/
void get_server_ip(char * server, addrinfo **serverResult)
{
	struct addrinfo hints;

	memset (&hints, 0, sizeof (hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_DGRAM;
	if ((getaddrinfo(server, NULL, &hints, serverResult)) != 0)
	{
		fprintf(stderr, "Could not get any info about %s!\n", server);
		exit(1);
	}
}

/*
*	Sets type and class of question.
*/
void set_type_and_class(question *questionItems, bool reverse, bool AAAAFlag)
{
	
	if (reverse == true)
	{
		questionItems->type = ntohs(PTR);
	}
	else if (AAAAFlag == true)
	{
		questionItems->type = ntohs(AAAA);
	}
	else
	{
		questionItems->type = ntohs(A);
	}
	questionItems->classNum = ntohs(class_IN);	
}

/*
*	Prepares packet for sending query, calls functions for setting question name, type and class.
*/
int set_query(int addressSize, bool reverse, bool AAAAFlag, char *reverseAddress, char *address, char **packet)
{
	int packetSize = sizeof(header) + addressSize + 1 + NULL_CHAR_SIZE + sizeof(question);
	*packet = (char *) malloc(packetSize);
	memset(*packet, 0, packetSize);
	char *queryName = *packet + sizeof(header);
	queryName[0] = '.';
	memcpy(queryName + 1, reverse ? reverseAddress : address, addressSize + 1);
	string_transform(queryName, addressSize);
	set_type_and_class((question *) (*packet + sizeof(header) + addressSize + 2), reverse, AAAAFlag);
	return packetSize;
}

/*
*	Set all bits in DNS header.
*/
void set_dns_head(char *packet, bool recursion)
{
	header *DNS_head = (header *) packet;
	DNS_head->ID = (unsigned short) htons(getpid());
    DNS_head->QR = 0;
    DNS_head->opcode = 0;
    DNS_head->AA = 0;
    DNS_head->TC = 0;
    if (recursion == true)
    {
    	DNS_head->RD = 1;
    }
    else
    {
    	DNS_head->RD = 0;
    }
    DNS_head->RA = 0;
    DNS_head->Z = 0;
    DNS_head->AD = 0;
    DNS_head->CD = 1;
    DNS_head->rcode = 0;
    DNS_head->qCount = htons(1);
    DNS_head->ansCount = 0;
    DNS_head->authCount = 0;
    DNS_head->addCount = 0;
}

/*
*	Decomposes header of DNS respond and print usefull information on standard output. In case of error, it prints meaning of response code.
*/
void decompose_head(header *DNS_head)
{
	printf("Authoritative: ");
	if (DNS_head->AA == 1)
	{
		printf("Yes, ");
	}
	else
	{
		printf("No, ");
	}
	
	printf("Recursive: ");
	if ((DNS_head->RA == 1) && (DNS_head->RD == 1))
	{
		printf("Yes, ");
	}
	else
	{
		printf("No, ");
	}

	printf("Truncated: ");
	if (DNS_head->TC == 1)
	{
		printf("Yes\n");
	}
	else
	{
		printf("No\n");
	}

	switch (DNS_head->rcode)
	{
	case 1:
		printf("Format error\n");
		break;
	case 2:
		printf("Server failure\n");
		break;
	case 3:
		printf("Name error\n");
		break;
	case 4:
		printf("Not implemented\n");
		break;
	case 5:
		printf("Refused\n");
		break;
	default:
		break;
	}
}

/*
*	Auxiliary function for decompose_RR() function. Calls decompose_RR() as many times as number of RRs in section specifies.
*/
int decompose_section(int count, char *nameToPrint, char *buffer, char *sectionStart)
{
	int totalRead = 0;

	for (size_t i = 0; i < ntohs(count); i++)
	{
		memset(nameToPrint, 0, MAX_NAME_SIZE);
		char *RR = (char *) sectionStart + totalRead;
		totalRead += decompose_RR(RR, nameToPrint, buffer);
	}
	return totalRead;
}

/*
*	Creates socket for UDP packets, sends prepared packet and waits for respond. After respond has come, calls functions for decomposing
*	all sections.
*	Note: Socket is set to wait 4seconds for answer. If no answer appeared, program is exited with error code.
*/
void send_and_recieve(addrinfo *serverResult, char *packet, int packetSize, char *port)
{
	int sock = 0;
	char *buffer = NULL;
	header *DNS_head;
	int totalRead = 0;

	if ((sock = socket(serverResult->ai_family, SOCK_DGRAM, 0)) == -1)
	{
		fprintf(stderr,"Creation of socket failed\n");
		exit(1);
	}

	struct timeval time;
	time.tv_sec = 5;
	time.tv_usec = 0;
	setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (void *) &time, sizeof(time));

	((sockaddr_in *) serverResult->ai_addr)->sin_port = htons(strtol(port, NULL, 10));

    if (sendto(sock, (const char *) packet, packetSize, 0,  serverResult->ai_addr, serverResult->ai_addrlen) < 0)
	{
		fprintf(stderr,"Sending query failed\n");
    	exit(1);
	}

	buffer = (char *) malloc(MAX_UDP_PACKET_SIZE);
	memset(buffer, 0, MAX_UDP_PACKET_SIZE);
    if (recv(sock, (void *) buffer, MAX_UDP_PACKET_SIZE, MSG_PEEK) < 0)
	{
		fprintf(stderr, "Waiting for respond timed out. Server is not communicating or packet got lost.\n");
    	exit(1);
	}

	DNS_head = (header *) buffer;
	decompose_head(DNS_head);

	printf("Question section (%d)\n", ntohs(DNS_head->qCount));
	char *nameToPrint = (char *) malloc(MAX_NAME_SIZE);
	memset(nameToPrint, 0, MAX_NAME_SIZE);
	char *question = (char *) buffer + sizeof(header);
	totalRead += decompose_query(question, nameToPrint, buffer);

	printf("Answer section (%d)\n", ntohs(DNS_head->ansCount));
	totalRead += decompose_section(DNS_head->ansCount, nameToPrint, buffer, question + totalRead);

	printf("Authority section (%d)\n", ntohs(DNS_head->authCount));
	totalRead += decompose_section(DNS_head->authCount, nameToPrint, buffer, question + totalRead);

	printf("Additional section (%d)\n", ntohs(DNS_head->addCount));
	totalRead += decompose_section(DNS_head->addCount, nameToPrint, buffer, question + totalRead);
	free(buffer);
	free(nameToPrint);
}

int main(int argc, char *argv[])
{
	bool recursion = false;
	bool reverse = false;
	bool AAAAFlag = false;
	char *server = NULL;
	char *port = NULL;
	char const *defaultPort = "53";
	char *address = NULL;
	char c = 0;
	char *packet = NULL;
	int packetSize;
	struct addrinfo *serverResult = NULL;

	/*
	* Getting parameters and arguments of parameters.
	*/
	while(((c) = getopt(argc, argv, ":hrx6s:p:")) != -1)
	{
		switch(c)
		{
			case 'r':
				if (recursion == true)
				{
					fprintf(stderr, "Multiple appearance of same argument!\n");
					exit(1);
				}
				recursion = true;
				break;
			case 'x':
				if (reverse == true)
				{
					fprintf(stderr, "Multiple appearance of same argument!\n");
					exit(1);
				}
				reverse = true;
				break;
			case '6':
				if (AAAAFlag == true)
				{
					fprintf(stderr, "Multiple appearance of same argument!\n");
					exit(1);
				}
				AAAAFlag = true;
				break;
			case 's':
				if (server != NULL)
				{
					fprintf(stderr, "Multiple appearance of same argument!\n");
					exit(1);
				}
				server = optarg;
				break;
			case 'p':
				if (port != NULL)
				{
					fprintf(stderr, "Multiple appearance of same argument!\n");
					exit(1);
				}
				port = optarg;
				break;
			case 'h':
				printf("This is simple tool for DNS lookups.\n");
				printf("Use it like: ./dns [-r] [-x] [-6] -s server [-p port] address\n");
				printf("Where:\n");
				printf(" -r: recursion desired is set to 1\n");
				printf(" -x: reverse query\n");
				printf(" -6: query for IPv6 adress (AAAA query)\n");
				printf(" -s: IP address or domain name for DNS server\n");
				printf(" -p: port number, where should be query send\n");
				printf(" address: domain name or ip address for lookup:\n");
				return 0;
			case ':':
				fprintf(stderr, "Missing value for argument!\n");
				exit(1);
				break;
			case '?':
				fprintf(stderr, "Unknown argument!\n");
				exit(1);
				break;
		}
	}

	if (server == NULL)
	{
		fprintf(stderr, "Missing domain name or ip address of server!\n");
		exit(1);
	}

	/*
	* Searching for arguments not catched by getopt() function.
	*/
	for (int i = 1; i < argc; ++i)
	{
		if (argv[i] != port && argv[i] != server && argv[i][0] != '-')
		{
			if (address != NULL)
			{
				fprintf(stderr, "Unknown argument!\n");
				exit(1);
			}
			address = argv[i];
		}
	}

	if (address == NULL)
	{
		fprintf(stderr, "Missing adress for lookup!\n");
		exit(1);
	}

	if (port == NULL)
	{
		port = (char *) defaultPort;
	}
	else if (*port == '0')
	{
		fprintf(stderr, "Destination port cannot be 0!\n");
		exit(1);	
	}
	
	get_server_ip(server, &serverResult);

	int addressSize = 0;
	char * reverseAddress = (char *) malloc(MAX_REVERSE_ADDR_SIZE);
	memset(reverseAddress, 0, MAX_REVERSE_ADDR_SIZE);

	if (reverse == true)
	{
		addressSize = reverse_transform(address, reverseAddress);
	}
	else
	{
		addressSize = strlen(address);
	}

	packetSize = set_query(addressSize, reverse, AAAAFlag, reverseAddress, address, &packet);
	set_dns_head(packet, recursion);
	send_and_recieve(serverResult, packet, packetSize, port);

	free(serverResult);
	free(reverseAddress);
	free(packet);
	return 0;
}