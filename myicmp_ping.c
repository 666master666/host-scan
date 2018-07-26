#include<sys/socket.h>
#include<netinet/in.h>
#include<unistd.h>
#include<arpa/inet.h>
#include<errno.h>
#include<sys/time.h>
#include<stdio.h>
#include<string.h>
#include<fcntl.h>
#include<stdlib.h>
#include<sys/types.h>
int num = 1;
struct ip_hdr
{
	unsigned char h_len:4;
	unsigned char version:4;
    u_int8_t ip_tos;
    u_short ip_len;
    u_short ip_id;
    u_short ip_off;
    u_int8_t ip_ttl;
    u_int8_t ip_p;
};
struct icmp_hdr
{
	u_char icmp_type;
	u_char icmp_code;
	u_short icmp_cksum;
	u_short icmp_id;
	u_short icmp_seq;
    struct timeval time;
};
typedef struct parameter
{
	struct timeval wait_time;
	int probe_count;
	useconds_t  interval;
}parameter;

int err_sys(char *s)
{
	perror(s);
	return -1;
}

void tv_sub(struct timeval *out,struct timeval *in)
{
    if((out->tv_usec-= in->tv_usec) < 0)
    {
        --out->tv_sec;
        out->tv_usec += 1000000;
    }
    out->tv_sec -= in->tv_sec;
}
//计算校验和（16位二进制反码求和）
static ushort icmp_cksum(u_short *data, int len)
{
	register int nleft = len;
	u_short *w = data;
	u_short answer;
	int sum = 0;
	//使用32位累加器进行16bit的反馈计算
	while(nleft > 1)
	{
		sum += *w++;
		nleft -= 2;
	}

	//奇位补齐
	if(nleft == 1)
	{
		u_short u = 0;
		*(u_char*)(&u) = *(u_char*)w;
		sum += u;
	}

	//将反馈的16bit从高处移至低处
	sum =(sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);
	answer = ~sum;
	return answer;
}

static void packet(struct icmp_hdr *icmphead,int pid)
{
	icmphead->icmp_type = 8;
    icmphead->icmp_code = 0;
    icmphead->icmp_id = pid;
    icmphead->icmp_seq = num++;
	icmphead->icmp_cksum = 0; //必须得要有

    struct timeval tv;
                bzero(&tv,sizeof(tv));
    gettimeofday(&tv,NULL);
    icmphead->time = tv;
	icmphead->icmp_cksum = icmp_cksum((u_short*)icmphead,sizeof(struct icmp_hdr));
}

int icmp_ping(uint32_t ip,parameter *para)
{
	unsigned char sendbuf[72];
	unsigned char recvbuf[1500];
    char ipval[16];

	struct sockaddr_in dstaddr,srcaddr;
	dstaddr.sin_family = AF_INET;
	dstaddr.sin_addr.s_addr = ip;

	int rawsock = socket(AF_INET,SOCK_RAW,IPPROTO_ICMP);
	if(rawsock == -1)
		return err_sys("rawsock error");

	pid_t pid = getpid();
	bzero(sendbuf,sizeof(sendbuf));
	packet((struct icmp_hdr*)sendbuf,pid);

	fd_set readfds;
	FD_ZERO(&readfds);

	int ret = 0;
	int srclen = sizeof(srcaddr);
	while(para->probe_count--)
	{
		printf("%d probe\n",para->probe_count+1);
		//发包
		ret = sendto(rawsock,(char*)sendbuf,20+sizeof(struct icmp_hdr),0,(struct sockaddr*)&dstaddr,sizeof(dstaddr));
		FD_SET(rawsock,&readfds);
		//成功返回就绪的文件描述符个数，失败返回-1(设置errno),超时返回0
		int readn = select(rawsock+1,&readfds,NULL,NULL,&(para->wait_time));
		if(readn == -1)
		{
			if(errno == EINTR)
				continue;
			else
				return err_sys("select error");

		}
		else if(readn == 0)
		{//超时
			usleep(para->interval);
			continue;
		}
		else
		{
			int len = recvfrom(rawsock,&recvbuf,sizeof(recvbuf),0,(struct sockaddr*)&srcaddr,&srclen);
			if(ret < 0)
			{
				return err_sys("recvfrom error");
			}
			//unpacket
			struct ip_hdr *iph = (struct ip_hdr*)recvbuf;
			struct icmp_hdr *reply = (struct icmp_hdr*)(recvbuf+iph->h_len*4);

			if(reply->icmp_id == pid && reply->icmp_type == 0)
            {
                struct timeval timerecv;
                bzero(&timerecv,sizeof(timerecv));
                gettimeofday(&timerecv,NULL);

                tv_sub(&timerecv,&(reply->time));

                double rtt = timerecv.tv_sec*1000 + timerecv.tv_usec/1000;

                printf("%d bytes from %s:icmp_seq = %u ttl = %d rtt = %.3f ms\n",
                        len,
                        inet_ntop(AF_INET,&ip,ipval,sizeof(ipval)),
                        reply->icmp_seq,
                        iph->ip_ttl,
                        rtt);

                return 0;
            }
            else
            {
                usleep(para->interval);
                continue;
            }
        }
    }
    return -1;

}

int main(int argc,char *argv[])
{
    parameter para;
    para.wait_time.tv_sec = 60;
    para.wait_time.tv_usec = 0;
    para.probe_count = 3;
    para.interval = 1*1000*1000;

    uint32_t ip;
    inet_pton(AF_INET,argv[1],&ip);

    int ret = icmp_ping(ip,&para);

    if(ret == 0)
        printf("open\n");
    else
        printf("down");

    return 0;

}

