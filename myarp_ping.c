#include<netinet/ip.h>
#include<sys/socket.h>
#include<netinet/in.h>
#include<netinet/tcp.h>
#include<unistd.h>
#include<signal.h>
#include<arpa/inet.h>
#include<errno.h>
#include<sys/time.h>
#include<stdio.h>
#include<string.h>
#include<netdb.h>
#include<pthread.h>
#include<fcntl.h>
#include<stdlib.h>
#include<netinet/if_ether.h>
#include<sys/ioctl.h>
#include<net/if.h>
#include<net/if_arp.h>
#include<netpacket/packet.h>
#include<net/ethernet.h>
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

static void packet(char *sendbuf,struct ifreq *ifr,uint32_t ip,int rawsock)
{
	//填充以太网头 目的MAC，源MAC,协议类型
	struct ether_header *hd = (struct ether_header*)sendbuf;
	unsigned char dst_mac[] = {
		0xff,0xff,0xff,0xff,0xff,0xff
	};
	memcpy(hd->ether_dhost,dst_mac,sizeof(dst_mac));


	//获取网卡MAC地址
	if(-1 == ioctl(rawsock,SIOCGIFHWADDR,ifr))
		err_sys("ioctl siocgifhwaddr error");
	memcpy(hd->ether_shost,ifr->ifr_hwaddr.sa_data,ETH_ALEN);

	hd->ether_type = htons(ETHERTYPE_ARP);

	//填充ARP请求数据包
	struct ether_arp *arp = (struct ether_arp*)(sendbuf+sizeof(struct ether_header));
	//硬件类型
	arp->arp_hrd = htons(ARPHRD_ETHER);
	//协议类型
	arp->arp_pro = htons(ETHERTYPE_IP);
	//硬件类型长度
	arp->arp_hln = ETH_ALEN;
	//协议类型长度
	arp->arp_pln = 4;
	//操作码 ARP请求
	arp->arp_op = htons(ARPOP_REQUEST);
	//发送端以太网地址
	memcpy(arp->arp_sha,ifr->ifr_hwaddr.sa_data,ETH_ALEN);

	//获取网卡IP
	if(-1 == ioctl(rawsock,SIOCGIFADDR,ifr))
		err_sys("ioctl siocgifaddr error");
	struct sockaddr_in *addr = (struct sockaddr_in*)(&(ifr->ifr_addr));

	char sipi[20];
	printf("sip:%s\n",inet_ntop(AF_INET,&(addr->sin_addr.s_addr),sipi,sizeof(sipi)));

	//发送端IP地址
	memcpy(arp->arp_spa,&(addr->sin_addr.s_addr),4);

	//目的端ip地址
	memcpy(arp->arp_tpa,&ip,4);
}

int arp_ping(uint32_t ip,parameter *para)
{
	unsigned char sendbuf[64];
	unsigned char recvbuf[1500];

	//创建原始套接字
	int rawsock = socket(PF_PACKET,SOCK_RAW,htons(ETH_P_ARP));
	if(rawsock == -1)
		return err_sys("rawsock error");


	struct ifreq ifr;
	memset(&ifr,0,sizeof(ifr));
	strcpy(ifr.ifr_name,"eth2");

	//获取网卡接口号
	if(-1 == ioctl(rawsock,SIOCGIFINDEX,&ifr))
		return err_sys("ioctl siocgiifindex error");

	//将网卡接口号绑定地址结构中
	struct sockaddr_ll dstaddr;
	bzero(&dstaddr,sizeof(dstaddr));
	dstaddr.sll_family = PF_PACKET;
	dstaddr.sll_ifindex = ifr.ifr_ifindex;

	//构造arp请求包
	bzero(sendbuf,sizeof(sendbuf));
	packet(sendbuf,&ifr,ip,rawsock);
	
	fd_set readfds;
	FD_ZERO(&readfds);
	int ret = 0;
	while(para->probe_count--)
	{
		printf("%d probe\n",para->probe_count+1);
		//发包
		ret = sendto(rawsock,(char*)sendbuf,60,0,(struct sockaddr*)&dstaddr,sizeof(dstaddr));

		if(ret < 0)
			return err_sys("sendto error");

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
			printf("outtime\n");
			usleep(para->interval);
			continue;
		}
		else
		{
			int len = recvfrom(rawsock,(char*)&recvbuf,sizeof(recvbuf),0,NULL,NULL);
			if(ret < 0)
			{
				return err_sys("recvfrom error");
			}
			//unpacket
			//以太网类型是ARP包，源ip是请求ip操作码是2
			struct ether_header *ethhdr = (struct ether_header*)recvbuf;
			struct ether_arp *arp = (struct ether_arp*)(recvbuf+sizeof(struct ether_header));
			if(ntohs(ethhdr->ether_type) == ETHERTYPE_ARP)
			{
				uint32_t sip;
				memcpy(&sip,arp->arp_spa,4);
				if(ntohs(arp->arp_op) == 2 && sip == ip)
				{
					close(rawsock);
					return 0;

				}
			}
			else
			{
				usleep(para->interval);
				continue;
			}
		}
	}
	close(rawsock);
	return -1;

}

int main(int argc,char *argv[])
{
	parameter para;
	para.wait_time.tv_sec = 6;
	para.wait_time.tv_usec = 0;
	para.probe_count = 3;
	para.interval = 1*1000*1000; 

	uint32_t ip;
	inet_pton(AF_INET,argv[1],&ip);

	int ret = arp_ping(ip,&para);

	if(ret == 0)
		printf("open\n");
	else
		printf("down");


	return 0;

}

