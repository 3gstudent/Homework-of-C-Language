#include <WinSock2.h>
#include <stdlib.h>
#pragma comment(lib, "Ws2_32")

int scan(int Ip,int Port)
{  
    	WSADATA wsaData;
    	SOCKET s;
	
    	WSAStartup(MAKEWORD(2, 2), &wsaData);
	s = socket(AF_INET, SOCK_STREAM, 0);
	if (s == INVALID_SOCKET) 
	{
		printf("[!]socket error\n");
		return 1;
	}
	
	unsigned long mode=1; 
	if(ioctlsocket(s, FIONBIO, (unsigned long*)&mode) == SOCKET_ERROR)
	{
		printf("[!]ioctlsocket error\n");
		return 1;
	}
	
	struct sockaddr_in addr;
	memset( &addr, 0, sizeof(addr)); 
	
    	addr.sin_family = AF_INET;
    	addr.sin_addr.s_addr = Ip;		
	addr.sin_port = htons(Port); 
	
	connect(s, (struct sockaddr *)&addr, sizeof(addr));
	struct timeval timeout ;
	fd_set r;
	
	FD_ZERO(&r);
	FD_SET(s, &r);
	timeout.tv_sec = 3;
	timeout.tv_usec =0;

	int ret = select(0, 0, &r, 0, &timeout); 
	
	in_addr inaddr;
	inaddr.s_addr = Ip;

    	if(ret<=0)
		printf("%s\n",inet_ntoa(inaddr));
	else
		printf("%s:%d\n",inet_ntoa(inaddr),Port);
	
	closesocket(s);
    	WSACleanup();
    	return 1;
}

int main(int argc, char *argv[])
{
	if (argc != 4)
	{
		printf("[!]Wrong parameter\n");
		printf("Usage:\n");
		printf(" %s <port> <BeginIP> <EndIP>\n", argv[0]);
		return 0;
	}
	else
	{
		int begin = inet_addr(argv[2]);
		int end = inet_addr(argv[3]);
		for(int i=begin;i<=end;i+=16777216)
			scan(i, atoi(argv[1]));
	}
}
