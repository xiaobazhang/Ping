#include <iostream>
#include <netinet/in.h>
#include "ip_icmp.h"
#include <unistd.h>
#include <netdb.h>
#include <map>
#include <signal.h>
#include <sys/time.h>
#include <arpa/inet.h>


#define BUF_SIZE 4096

#define ICMP_SIZE 64

int message_send;
int message_recv;

char *hostname;
char recvbuf[BUF_SIZE];
char sendbuf[ICMP_SIZE];
void hand_sig(int sig); // 信号处理函数
int64_t start_now;



int resolve(const char* hostname, int port, struct sockaddr_in *addr);
int64_t now();
void registSignal(int sig, void (*handler)(int));
void run();
unsigned short cksum(unsigned short *addr, int len);

int main(int argc, char* argv[]) {
	if(argc < 2){
		printf("Usage: %s <hostname or ip>\n", argv[0]);
	}
	hostname = argv[1];
	registSignal(SIGALRM, hand_sig);
	registSignal(SIGINT, hand_sig);
	run();
	return 0;
}


void run(){

	struct ip *ip; // ip首部
	struct icmp_echo *icmp_request, *icmp_reply;
	struct sockaddr_in to;
	int len,sockfd, ret, nr;
	int64_t time_send,time_recv;
	double rtt;

	message_send = 0;
	message_recv = 0;

	// 随机初始化
	for (int i = 0;i < ICMP_SIZE;++i){
		sendbuf[i] = "abcdefghijklmnopqrstuvwxyz"[i%26];
	}

	ret = resolve(hostname,0,&to);
	if(ret < 0){
		printf("get hostname failed!!\n");
		return;
	}

	sockfd = socket(AF_INET,SOCK_RAW,IPPROTO_ICMP);
	if(sockfd < 0){
		printf("created socker failed!!\n");
		return;
	}

	printf("PING %s (%s) %d bytes of data.\n",hostname,inet_ntoa(to.sin_addr),ICMP_SIZE);

	icmp_request = (struct icmp_echo*)sendbuf;
	ip = (struct ip*)recvbuf;

	start_now = now();

	icmp_request->icmp_type = 8;
	icmp_request->icmp_code = 0;
	icmp_request->icmp_id = getpid() & 0xffff;

	while(true)
	{
		icmp_request->icmp_cksum = 0;
		icmp_request->icmp_seq = message_send + 1;
		*((int64_t*)icmp_request->icmp_data) = now();
		icmp_request->icmp_cksum = cksum((unsigned short*)sendbuf, ICMP_SIZE);

		ret = sendto(sockfd,sendbuf,ICMP_SIZE,0,(struct sockaddr*)&to, sizeof(to));
		if(ret < 0){
			if (errno == EINTR){
				continue;
			}
			printf("stop sendto\n");
			return ;
		}
		++message_send;

		again:
			alarm(5);
		nr = recvfrom(sockfd,recvbuf,BUF_SIZE,0,NULL,NULL);
		if(nr < 0){
			if (errno == EINTR) {
				printf("TIMEDOUT.\n");
				continue; // 超时，丢包
			}
			printf("recvfrom");
		}

		icmp_reply = (struct icmp_echo*)((char*)ip + (ip->ip_hl << 2));
		if(icmp_reply->icmp_type !=0 || icmp_reply->icmp_code !=0
			|| icmp_reply->icmp_id != (getpid() & 0xffff)){
			goto again;
		}

		++message_recv;

		time_recv = now();

		time_send = *((int64_t*)icmp_reply->icmp_data);

		rtt = (time_recv-time_send)/1000.0;

		printf("%d bytes from %s (%s): icmp_seq=%d ttl=%d time=%.1f ms\n", ICMP_SIZE, hostname, inet_ntoa(to.sin_addr), icmp_reply->icmp_seq, ip->ip_ttl, rtt);

		sleep(1);
	}

}

void hand_sig(int sig){
	int64_t  end;
	if(sig == SIGINT){
		end = now();
		printf("\n--- %s ping statistics ---\n", hostname);
		printf("%d packets transmitted, %d received, %d%% packet loss, time %dms\n", message_send, message_recv, (message_send - message_recv) * 100 / message_send, (int)(end - start_now) / 1000);
		exit(0);
	}
}


int resolve(const char* hostname, int port, struct sockaddr_in *addr) {
	int ret;
	struct hostent *he;

	bzero(addr, sizeof(struct sockaddr_in));

	ret = inet_aton(hostname, &addr->sin_addr);
	if (ret == 0) {
		he = gethostbyname(hostname);
		errno = h_errno;
		if (!he) return -1;
		addr->sin_addr= *(struct in_addr*)(he->h_addr);
	}

	addr->sin_family = AF_INET;
	addr->sin_port = htons((short)port);

	return 0;
}

int64_t now() {
	int ret;
	struct timeval now;
	ret = gettimeofday(&now, NULL);
	if (ret < 0) printf("gettimeofday\n");
	return now.tv_sec * 1000000 + now.tv_usec;
}

unsigned short cksum(unsigned short *addr, int len){
	unsigned int sum = 0;
	while(len > 1){
		sum += *addr++;
		len -= 2;
	}

	// 处理剩下的一个字节
	if(len == 1){
		sum += *(unsigned char*)addr;
	}

	// 将32位的高16位与低16位相加
	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);

	return (unsigned short) ~sum;
}

void registSignal(int sig, void (*hand_sig)(int)) {
	struct sigaction sa, old;
	sa.sa_handler = hand_sig;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;
	if (sigaction(sig, &sa, &old) < 0) {
		printf("sigaction\ns");
	}

	//if (oldhandler)
	//	*oldhandler = old.sa_handler;
}