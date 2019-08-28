#pragma comment( lib, "ws2_32.lib" )
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <stdlib.h>
#include <math.h>

#define IP_RECORD_ROUTE 0x7
#define DEF_PACKET_SIZE 32
#define MAX_PACKET 1024
#define MAX_IP_HDR_SIZE 60
#define ICMP_ECHO 8
#define ICMP_ECHOREPLY 0
#define ICMP_MIN 8

void InitPing();
void GetArgments(int argc, char **argv);
void UserHelp();
void PingTest(int timeout);
USHORT CheckSum(USHORT *buffer, int size);
void FillICMPData(char *icmp_data, int datasize);
void DecodeIpOptions(char *buf, int bytes);
void DecodeICMPHeader(char *buf, int bytes, SOCKADDR_IN *from);
void FreeRes();

typedef struct _iphdr{
	unsigned int h_len : 4;
	unsigned int version : 4;
	unsigned char tos;
	unsigned short total_len;
	unsigned short ident;
	unsigned short frag_flags;
	unsigned char ttl;
	unsigned char proto;
	unsigned short checksum;
	unsigned int sourceIP;
	unsigned int destIP;
}IpHeader;
typedef struct _icmphdr{
	BYTE i_type;
	BYTE i_code;
	USHORT i_cksum;
	USHORT i_id;
	USHORT i_seq;
	ULONG timestamp;
}IcmpHeader;
typedef struct _ipoptionhdr{
	unsigned char code;
	unsigned char len;
	unsigned char ptr;
	unsigned long addr[9];
}IpOptionHeader;

SOCKET m_socket;
IpOptionHeader IpOption;
SOCKADDR_IN DestAddr;
SOCKADDR_IN SourceAddr;
char *icmp_data;
char *recvbuf;
USHORT seq_no;
char *lpdest;
int datasize;
BOOL RecordFlag;
double PacketNum;
BOOL SucessFlag;


int main(int argc, char *argv[])
{
	InitPing();
	GetArgments(argc, argv);
	PingTest(1000);
	Sleep(1000);
	if (SucessFlag)
		printf("Ping end, you have got %.0f records!\n", PacketNum);
	else
		printf("Ping end, no record!\n");
	FreeRes();
	//	system("pause");
	return 0;
}

void InitPing()
{
	WSADATA wsaData;
	icmp_data = NULL;
	seq_no = 0;
	recvbuf = NULL;
	RecordFlag = FALSE;
	lpdest = NULL;
	datasize = DEF_PACKET_SIZE;
	PacketNum = 5;
	SucessFlag = FALSE;
	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
	{
		printf("WSAStartup() failed: %d\n", GetLastError());
		return;
	}
	m_socket = INVALID_SOCKET;
}

void GetArgments(int argc, char **argv)
{
	int i, j, exp, len;
	if (argc <= 1)
	{
		printf("Too few parameter,check your input.\n");
		UserHelp();
	}
	if (argv[0][0] != 'p' || argv[0][1] != 'i' || argv[0][2] != 'n' || argv[0][3] != 'g')
		UserHelp();
	for (i = 1; i < argc; i++)
	{
		len = strlen(argv[i]);
		if (argv[i][0] == '-')
		{
			switch (tolower(argv[i][1]))
			{
			case 'r':
				RecordFlag = TRUE;
				break;
			case 'n':
				len = strlen(argv[i + 1]);
				PacketNum -= 5;
				for (j = 0, exp = len - 1; j < len; j++, exp--)
					PacketNum += (DOUBLE)(argv[i + 1][j] - '0')*pow(10, exp);
				i++;
				break;
			default:
				UserHelp();
				break;
			}
		}
		else if (isdigit(argv[i][0]))
		{
			for (j = 0; j < len; j++)
			{
				if (!isdigit(argv[i][j]))
				{
					lpdest = argv[i];
					continue;
				}
				if (j == len - 1)
					datasize = atoi(argv[i]);
			}
		}
		else
			lpdest = argv[i];
	}
}

void UserHelp()
{
	printf(" UserHelp: ping -r <host> [datasize]\n");
	printf("        -r      record route\n");
	printf("        -n      record mount\n");
	printf("       host     remote machine to ping\n");
	printf("     datasize   can be up to 1Kb\n");
	ExitProcess(-1);
}

USHORT CheckSum(USHORT *buffer, int size)
{

	unsigned long cksum = 0;
	while (size > 1)
	{
		cksum += *buffer++;
		size -= sizeof(USHORT);
	}
	if (size)
		cksum += *(UCHAR*)buffer;
	cksum = (cksum >> 16) + (cksum & 0xffff);
//	cksum += (cksum >> 16);
	return (USHORT)(~cksum);
}

void PingTest(int timeout)
{
	int ret, readNum, fromlen;
	struct hostent *hp = NULL;
	m_socket = WSASocket(AF_INET, SOCK_RAW, IPPROTO_ICMP, NULL, 0, WSA_FLAG_OVERLAPPED);
	if (m_socket == INVALID_SOCKET)
		printf("WSASocket() failed: %d\n", WSAGetLastError());
	if (RecordFlag)
	{
		ZeroMemory(&IpOption, sizeof(IpOption));
		IpOption.code = IP_RECORD_ROUTE;
		IpOption.ptr = 4;
		IpOption.len = 39;
		ret = setsockopt(m_socket, IPPROTO_IP, IP_OPTIONS, (char*)&IpOption, sizeof(IpOption));
		if (ret == SOCKET_ERROR)
		{
			printf("setsocketop(IP_OPTIONS) failed: %d\n", WSAGetLastError());
		}
	}
	readNum = setsockopt(m_socket, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));
	if (readNum == SOCKET_ERROR)
	{
		printf("setsockopt(SO_REVTIMEO) failed: %d\n", WSAGetLastError());
		return;
	}
	timeout = 1000;
	readNum = setsockopt(m_socket, SOL_SOCKET, SO_SNDTIMEO, (char*)&timeout, sizeof(timeout));
	if (readNum == SOCKET_ERROR)
	{
		printf("setsockopt(SO_SNDTIMEO) failed: %d\n", WSAGetLastError());
		return;
	}
	memset(&DestAddr, 0, sizeof(DestAddr));
	DestAddr.sin_family = AF_INET;
	if ((DestAddr.sin_addr.s_addr = inet_addr(lpdest)) == INADDR_NONE)
	{
		if ((hp = gethostbyname(lpdest)) != NULL)
		{
			memcpy(&(DestAddr.sin_addr), hp->h_addr, hp->h_length);
			DestAddr.sin_family = hp->h_addrtype;
			printf("DestAddr.sin_addr=%s\n", inet_ntoa(DestAddr.sin_addr));
		}
		else
		{
			printf("gethostbyname() failed: %d\n", WSAGetLastError());
			return;
		}
	}
	datasize += sizeof(IcmpHeader);
	icmp_data = (char*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, MAX_PACKET);
	recvbuf = (char*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, MAX_PACKET);
	if (!icmp_data || !recvbuf)
	{
		printf("HeapAlloc() failed: %d\n", GetLastError());
		return;
	}
	memset(icmp_data, 0, MAX_PACKET);
	FillICMPData(icmp_data, datasize);
	while (1)
	{
		static int nCount = 0;
		int writeNum;
		if (nCount++ == PacketNum)
			break;
		((IcmpHeader*)icmp_data)->i_cksum = 0;
		((IcmpHeader*)icmp_data)->timestamp = GetTickCount();
		((IcmpHeader*)icmp_data)->i_seq = seq_no++;
		((IcmpHeader*)icmp_data)->i_cksum = CheckSum((USHORT*)icmp_data, datasize);
		writeNum = sendto(m_socket, icmp_data, datasize, 0, (struct sockaddr*)&DestAddr, sizeof(DestAddr));
		if (writeNum == SOCKET_ERROR)
		{
			if (WSAGetLastError() == WSAETIMEDOUT)
			{
				printf("timed out\n");
				continue;
			}
			printf("sendto() failed: %d\n", WSAGetLastError());
			return;
		}
		fromlen = sizeof(SourceAddr);
		readNum = recvfrom(m_socket, recvbuf, MAX_PACKET, 0, (struct sockaddr*)&SourceAddr, &fromlen);
		if (readNum == SOCKET_ERROR)
		{
			if (WSAGetLastError() == WSAETIMEDOUT)
			{
				printf("timed out\n");
				continue;
			}
			printf("recvfrom() failed: %d\n", WSAGetLastError());
			return;
		}
		DecodeICMPHeader(recvbuf, readNum, &SourceAddr);
	}

}


void FillICMPData(char *icmp_data, int datasize)
{
	IcmpHeader *icmp_hdr = NULL;
	char *datapart = NULL;
	icmp_hdr = (IcmpHeader*)icmp_data;
	icmp_hdr->i_type = ICMP_ECHO;
	icmp_hdr->i_code = 0;
	icmp_hdr->i_id = (USHORT)GetCurrentProcessId();
	icmp_hdr->i_cksum = 0;
	icmp_hdr->i_seq = 0;
	datapart = icmp_data + sizeof(IcmpHeader);
	memset(datapart, '0', datasize - sizeof(IcmpHeader));
}

void DecodeIpOptions(char *buf, int bytes)
{
	IpOptionHeader *ipopt = NULL;
	IN_ADDR inaddr;
	int i;
	HOSTENT *host = NULL;
	ipopt = (IpOptionHeader*)(buf + 20);
	printf("RR:");
	for (i = 0; i < (ipopt->ptr / 4) - 1; i++)
	{
		inaddr.S_un.S_addr = ipopt->addr[i];
		if (i != 0)
			printf("	");
		host = gethostbyaddr((char*)&inaddr.S_un.S_addr, sizeof(inaddr.S_un.S_addr), AF_INET);
		if (host)
			printf("(%-15s) %s\n", inet_ntoa(inaddr), host->h_name);
		else
			printf("(%-15s)\n", inet_ntoa(inaddr));
	}
}

void DecodeICMPHeader(char *buf, int bytes, SOCKADDR_IN *from)
{
	IpHeader *iphdr = NULL;
	IcmpHeader *icmphdr = NULL;
	unsigned short iphdrlen = 0;
	DWORD tick;
	static int icmpcount = 0;
	iphdr = (IpHeader*)buf;
	iphdrlen = iphdr->h_len * 4;
	tick = GetTickCount();
	if (iphdrlen == MAX_IP_HDR_SIZE&&icmpcount == 0)
		DecodeIpOptions(buf, bytes);
	if (bytes < iphdrlen + ICMP_MIN)
	{
		printf("Too few bytes from %s\n", inet_ntoa(from->sin_addr));
	}
	icmphdr = (IcmpHeader*)(buf + iphdrlen);
	if (icmphdr->i_type != ICMP_ECHOREPLY)
	{
		printf("nonecho type %d recvd\n", icmphdr->i_type);
		return;
	}
	if (icmphdr->i_id != (USHORT)GetCurrentProcessId())
	{
		printf("someone else's packet!\n");
		return;
	}
	SucessFlag = TRUE;
	printf("%d bytes from %s:", bytes, inet_ntoa(from->sin_addr));
	printf("icmp_seq=%d. ", icmphdr->i_seq);
	printf("time: %d ms\n", tick - icmphdr->timestamp);
	icmpcount++;
}

void FreeRes()
{
	if (m_socket != INVALID_SOCKET)
		closesocket(m_socket);
	HeapFree(GetProcessHeap(), 0, recvbuf);
	HeapFree(GetProcessHeap(), 0, icmp_data);
	WSACleanup();
}