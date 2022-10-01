/*
* Login: xkrajc21
*/

#define A 1
#define NS 2
#define MD 3
#define MF 4
#define CNAME 5
#define SOA 6
#define MB 7
#define MG 8
#define MR 9
#define RR_NULL 10
#define WKS 11
#define PTR 12
#define HINFO 13
#define MINFO 14
#define MX 15
#define TXT 16
#define AAAA 28

#define class_IN 1
#define class_CS 2
#define class_CH 3
#define class_HS 4

#define DOT_SIZE 1
#define NULL_CHAR_SIZE 1
#define NAME_ADDRESS_SIZE 2
#define MAX_NAME_SIZE 255
#define MAX_UDP_PACKET_SIZE 512
#define MAX_REVERSE_ADDR_SIZE 73
#define IPV4_BYTE_FORMAT_SIZE 4
#define IPV6_BYTE_FORMAT_SIZE 16

#define type(RR_type)     case RR_type: printf(#RR_type", ");

struct header
{
    uint16_t ID;
# if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
	uint8_t QR:1;
	uint8_t opcode:4;
	uint8_t AA:1;
	uint8_t TC:1;
	uint8_t RD:1;
	uint8_t RA:1;
	uint8_t Z:1;
    uint8_t AD:1;
    uint8_t CD:1;
	uint8_t rcode:4;
# else   
    uint8_t RD :1;
    uint8_t TC :1;
    uint8_t AA :1;
    uint8_t opcode :4;
    uint8_t QR :1;
    uint8_t rcode :4;
    uint8_t CD :1;
    uint8_t AD :1;
    uint8_t Z :1;
    uint8_t RA :1;
# endif
    uint16_t qCount;
    uint16_t ansCount;
    uint16_t authCount;
    uint16_t addCount;
}__attribute__((packed));

struct question
{
	uint16_t type;
	uint16_t classNum;
}__attribute__((packed));

struct RR
{
	uint16_t type;
	uint16_t classNum;
	uint32_t TTL;
	uint16_t dataLenght;
}__attribute__((packed));

struct SOA_rdata
{
    uint32_t serial;
    uint32_t refresh;
    uint32_t retry;
    uint32_t expire;
    uint32_t mininum;
}__attribute__((packed));

int read_name(char *namePtr, char *nameToPrint, char *buffer);
int read_label(char *namePtr, char *nameToPrint, char *buffer);
int decompose_query(char *namePtr, char *nameToPrint, char *buffer);
int decompose_rdata_mx(char *rdata_start, char *nameToPrint, char *buffer);
int decompose_rdata_soa(char *rdata_start, char *nameToPrint, char *buffer);
int decompose_RR(char *namePtr, char *nameToPrint, char *buffer);
int reverse_transform (char *address, char *reverseAddress);
void string_transform(char * queryName, int addressSize);
void get_server_ip(char * server, addrinfo **serverResult);
void set_type_and_class(question *questionItems, bool reverse, bool AAAAFlag);
int set_query(int addressSize, bool reverse, bool AAAAFlag, char *reverseAddress, char *address, char **packet);
void set_dns_head(char *packet, bool recursion);
void decompose_head(header *DNS_head);
int decompose_section(int count, char *nameToPrint, char *buffer, char *sectionStart);
void send_and_recieve(addrinfo *serverResult, char *packet, int packetSize, char *port);