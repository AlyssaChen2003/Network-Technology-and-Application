#define WIN32
#define HAVE_REMOTE
#define WIN32
#define WPCAP
#define HAVE_REMOTE
#include "pcap.h"
#include <iostream>
#include<WinSock2.h>
#include<bitset>
#include <process.h>
using namespace std;
#pragma comment(lib,"wpcap.lib")
#pragma comment(lib, "packet.lib")
#pragma comment(lib,"ws2_32.lib")
#pragma warning(disable:4996)
#pragma pack(1)
#define BYTE unsigned char
using namespace std;
//#include "Release/pcap.h"
#include <bitset>
#include <process.h>
#include <stdio.h>
#pragma comment(lib,"wpcap.lib")
#pragma comment(lib,"ws2_32.lib")
#pragma warning(disable:4996)
#define _CRT_SECURE_NO_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS


pcap_if_t* alldevs;
pcap_if_t* d;
pcap_t* choosed_dev;//open的网卡
pcap_addr* a;//网卡对应的地址
char errbuf[PCAP_ERRBUF_SIZE];
char ip[10][20];
char mask[10][20];
BYTE my_mac[6];

#pragma pack(1)//以1byte方式对齐
typedef struct FrameHeader_t {//帧首部
	BYTE DesMAC[6];
	BYTE SrcMAC[6];
	WORD FrameType;
}FrameHeader_t;
typedef struct ARPFrame_t {//ARP首部
	FrameHeader_t FrameHeader;
	WORD HardwareType;
	WORD ProtocolType;
	BYTE HLen;
	BYTE PLen;
	WORD Operation;
	BYTE SendHa[6];
	DWORD SendIP;
	BYTE RecvHa[6];
	DWORD RecvIP;
}ARPFrame_t;
typedef struct IPHeader_t {//IP首部
	BYTE Ver_HLen;
	BYTE TOS;
	WORD TotalLen;
	WORD ID;
	WORD Flag_Segment;
	BYTE TTL;
	BYTE Protocol;
	WORD Checksum;
	ULONG SrcIP;
	ULONG DstIP;
}IPHeader_t;
typedef struct ICMPHeader_t {// ICMP首部
	BYTE    Type;
	BYTE    Code;
	WORD    Checksum;
	WORD    Id;
	WORD    Sequence;
} ICMPHeader_t;
typedef struct IPFrame_t {//包含帧首部和IP首部的数据包
	FrameHeader_t FrameHeader;
	IPHeader_t IPHeader;
}IPFrame_t;
class RouteItem//路由表项
{
public:
	RouteItem* next;
	int index;//索引
	DWORD mask;//掩码
	DWORD dst_net;//目的网络
	DWORD next_ip;//下一跳的IP地址
	BYTE nextMAC[6];//下一跳的MAC地址
	int type;//0为直接连接（不可删除），1为用户添加
	RouteItem() { memset(this, 0, sizeof(*this)); }
	void print();
};
class RouteTable
{
public:
	int count;//条数
	RouteTable();//初始化，添加直接连接的网络
	void insert(RouteItem* a);//添加路由表项，直接相连的在最前面，其余按最长匹配原则
	void remove(int index);//删除第i条路由表项（直接相连的不可删除
	void print();
	DWORD lookup(DWORD ip);//根据最长匹配原则，查找下一跳的ip地址
	RouteItem* head, * tail;//路由表项
};
#pragma pack()//恢复4bytes对齐
typedef struct SendPacket_t {	  // 发送数据包结构
	int				len;          // 长度
	BYTE			PktData[2000];// 数据缓存
	ULONG			TargetIP;     // 目的IP地址
	bool			flag = 1;	  // 是否有效，如果已经被转发或者超时，则置0
	clock_t         t;            // 超时判断
} SendPacket_t;
class arptable
{
public:
	DWORD ip;
	BYTE mac[6];
	static int num;
	static void insert(DWORD ip, BYTE mac[6]);
	static int lookup(DWORD ip, BYTE mac[6]);
}ip_mac_table[50];
//日志类
class my_log
{
public:
	my_log();
	~my_log();

	static FILE* fp;
	//写入日志
	static void write_arp_log(const char* a, ARPFrame_t*);//arp类型
	static void write_arp_log(const char* a, ARPFrame_t);//arp类型
	static void write_ip_log(const char* a, IPFrame_t*);//ip类型
	static void write_icmp_log(const char* a);//icmp类型
}my_log;
bool Compare(BYTE a[], BYTE b[]);//比较两个MAC地址是否相同
void get_my_ip();	//获取本机的设备列表，将两个ip存入ip数组中,获取IP、mask，计算所在网段
void get_my_mac(DWORD ip);//获取本机的MAC
void printf_mac(BYTE MAC[]);//打印mac
unsigned short cal_checksum(unsigned short* buffer, int size);
int test_checksum(char* buffer);
void* get_in_addr(struct sockaddr* sa)
{
	if (sa->sa_family == AF_INET)
		return &(((struct sockaddr_in*)sa)->sin_addr);
	return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

// 发送ICMP数据包
void ICMPPacketProc(BYTE type, BYTE code, const u_char* pkt_data);
//线程函数
DWORD WINAPI recv(LPVOID lparam);
//多线程
HANDLE hThread;
DWORD dwThreadId;
//::std::vector<SendPacket_t> my_Buffer;   
SendPacket_t my_Buffer[50];  // 发送数据包缓存数组 由于vector的删除操作要用到Windows 2003中不支持的mutex类，所以改成数组形式
clock_t buffer_timeout[50];//缓存区中该报文存放时间，超时删除
int totalcount = 0;  //记录缓存区中的总个数
int main(){
	//获取本机ip
	get_my_ip();
	for (int i = 0; i < 2; i++)
	{
		printf("%s\t", ip[i]);
		printf("%s\n", mask[i]);
	}
	get_my_mac(inet_addr(ip[0]));
	printf_mac(my_mac);

	RouteTable router_table;
	hThread = CreateThread(NULL, NULL, recv, LPVOID(&router_table), 0, &dwThreadId);

	int j;
	while (1)
	{
		printf("\n\n请选择您要进行的操作：\n1. 添加路由表项\n2. 删除路由表项\n3. 打印路由表\n");
		scanf("%d", &j);
		RouteItem a;
		switch (j) {
		case 1:
			char t[30];
			printf("请输入掩码：");
			scanf("%s", &t);
			a.mask = inet_addr(t);
			printf("请输入目的网络：");
			scanf("%s", &t);
			a.dst_net = inet_addr(t);
			printf("请输入下一跳的IP地址：");
			scanf("%s", &t);
			a.next_ip = inet_addr(t);
			a.type = 1;
			router_table.insert(&a);
			break;
		case 2:
			printf("请输入您要删除的表项的索引：");
			int i;
			scanf("%d", &i);
			router_table.remove(i);
			break;
		case 3:
			router_table.print();
			break;
		default:
			printf("无效操作，请重新输入\n");
			break;
		}
	}
	return 0;

}

void get_my_ip()	//获取网卡上的IP
{
	pcap_if_t* d;
	pcap_addr_t* a;
	int i = 0;
	char errbuf[PCAP_ERRBUF_SIZE];
	if (pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		//cout << stderr << "Error in pcap_findalldevs:" << errbuf << endl;
	}
	for (d = alldevs; d; d = d->next)
	{
		printf("%d. %s", ++i, d->name);
		if (d->description)
			printf("( %s )\n", d->description);
		else
			printf("(No description available)\n");
		for (a = d->addresses; a != NULL; a = a->next) {
			if (a->addr->sa_family == AF_INET) {
				char str[INET_ADDRSTRLEN];
				strcpy(str, inet_ntoa(((struct sockaddr_in*)a->addr)->sin_addr));
				printf("IP地址：%s\n", str);
				strcpy(str, inet_ntoa(((struct sockaddr_in*)a->netmask)->sin_addr));
				printf("网络掩码：%s\n", str);
				strcpy(str, inet_ntoa(((struct sockaddr_in*)a->broadaddr)->sin_addr));
				printf("广播地址：%s\n", str);
			}
		}
	}
	if (i == 0)
	{
		printf("\nNo interfaces found! Makesure WinPcap is installed.\n");
	}
	printf("===============================================================================\n\n");
	d = alldevs;
	int j;
	printf("请选择您要打开的网卡：");
	scanf("%d", &j);
	for (i = 0; i < j - 1; i++) {
		d = d->next;
	}
	int t = 0;
	for (a = d->addresses; a != NULL; a = a->next) {
		if (a->addr->sa_family == AF_INET) {
			strcpy(ip[t], inet_ntoa(((struct sockaddr_in*)a->addr)->sin_addr));
			strcpy(mask[t++], inet_ntoa(((struct sockaddr_in*)a->netmask)->sin_addr));
		}
	}
	choosed_dev = pcap_open(d->name, 100, PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL, errbuf);
	if (choosed_dev == NULL) {
		pcap_freealldevs(alldevs);
	}
	pcap_freealldevs(alldevs);
}
bool Compare(BYTE a[6], BYTE b[6])
{
	bool index = true;
	for (int i = 0; i < 6; i++)
	{
		if (a[i] != b[i])
			index = false;
	}
	return index;
}
void get_my_mac(DWORD ip)
{
	memset(my_mac, 0, sizeof(my_mac));
	ARPFrame_t ARPFrame1;
	for (int i = 0; i < 6; i++) {
		ARPFrame1.FrameHeader.DesMAC[i] = 0xff;
		ARPFrame1.FrameHeader.SrcMAC[i] = 0x0f;
		ARPFrame1.SendHa[i] = 0x0f;
		ARPFrame1.RecvHa[i] = 0x00;
	}
	ARPFrame1.FrameHeader.FrameType = htons(0x0806);
	ARPFrame1.HardwareType = htons(0x0001);
	ARPFrame1.ProtocolType = htons(0x0800);
	ARPFrame1.HLen = 6;
	ARPFrame1.PLen = 4;
	ARPFrame1.Operation = htons(0x0001);
	ARPFrame1.SendIP = inet_addr("10.10.10.10");
	ARPFrame1.RecvIP = ip;
	struct pcap_pkthdr* pkt_header;
	const u_char* pkt_data;
	struct pcap_pkthdr* header = new pcap_pkthdr;
	int k;
	while ((k = pcap_next_ex(choosed_dev, &pkt_header, &pkt_data)) >= 0) {
		if (pcap_sendpacket(choosed_dev, (u_char*)&ARPFrame1, sizeof(ARPFrame_t)) != 0) {
			printf("Error in pcap_sendpacket");
			pcap_freealldevs(alldevs);
			break;
		}
		if (k == 0)continue;
		else if (*(unsigned short*)(pkt_data + 12) == htons(0x0806) && *(unsigned short*)(pkt_data + 20) == htons(0x0002)
			&& *(unsigned long*)(pkt_data + 28) == ARPFrame1.RecvIP) {
			for (int i = 0; i < 6; i++) {
				my_mac[i] = *(unsigned char*)(pkt_data + 22 + i);
			}
			break;
		}
	}
}
void get_mac_of(DWORD ip_)//获取ip对应的mac
{
	ARPFrame_t ARPFrame;
	//将APRFrame.FrameHeader.DesMAC设置为广播地址
	for (int i = 0; i < 6; i++)
		ARPFrame.FrameHeader.DesMAC[i] = 0xff;
	//将APRFrame.FrameHeader.SrcMAC设置为本机网卡的MAC地址
	for (int i = 0; i < 6; i++)
	{
		ARPFrame.FrameHeader.SrcMAC[i] = my_mac[i];
		ARPFrame.SendHa[i] = my_mac[i];
	}
	ARPFrame.FrameHeader.FrameType = htons(0x806);//帧类型为ARP
	ARPFrame.HardwareType = htons(0x0001);//硬件类型为以太网
	ARPFrame.ProtocolType = htons(0x0800);//协议类型为IP
	ARPFrame.HLen = 6;//硬件地址长度为6
	ARPFrame.PLen = 4;//协议地址长为4
	ARPFrame.Operation = htons(0x0001);//操作为ARP请求
	//将ARPFrame->SendIP设置为本机网卡上绑定的IP地址
	ARPFrame.SendIP = inet_addr(ip[0]);
	//将ARPFrame->RecvHa设置为0
	for (int i = 0; i < 6; i++)
		ARPFrame.RecvHa[i] = 0;
	ARPFrame.RecvIP = ip_;

	pcap_sendpacket(choosed_dev, (u_char*)&ARPFrame, sizeof(ARPFrame_t));
	my_log.write_arp_log("发送", ARPFrame);
}
void printf_mac(BYTE MAC[])//打印mac
{
	printf("MAC地址为： ");
	for (int i = 0; i < 5; i++)
		printf("%02X-", MAC[i]);
	printf("%02X\n", MAC[5]);
}


void RouteTable::insert(RouteItem* r)
{
	RouteItem* temp;

	if (count == 0) {
		head->next = r;
		r->next = NULL;
	}
	else {
		temp = head->next;
		while (temp != NULL) {

			if (temp->next == NULL || (r->mask < temp->mask && r->mask >= temp->next->mask)) {
				//printf("a\n");
				break;
			}
			temp = temp->next;
			//break;
		}
		if (temp->next == NULL)
		{
			//printf("here");
			r->next = NULL;
			temp->next = r;
		}
		else {
			r->next = temp->next;
			temp->next = r;
		}
	}
	RouteItem* p = head->next;
	//重新编号
	for (int i = 0; p != NULL; i++)
	{
		//printf("%d",p->mask);
		p->index = i;
		p = p->next;
	}
	count++;
	return;
}

void RouteItem::print()
{
	in_addr addr;
	printf("%d   ", index);
	addr.s_addr = mask;
	char* str = inet_ntoa(addr);
	printf("%s\t", str);

	addr.s_addr = dst_net;
	str = inet_ntoa(addr);
	printf("%s\t", str);

	addr.s_addr = next_ip;
	str = inet_ntoa(addr);
	printf("%s\t\t", str);

	printf("%d\n", type);
}
void RouteTable::print()
{
	//遍历路由表
	RouteItem* p = head->next;
	for (; p != tail; p = p->next)
	{
		p->print();
	}
}
//初始化路由表，添加直接连接的网络
RouteTable::RouteTable()
{
	head = new RouteItem;
	//tail = new RouteItem;
	head->next = NULL;
	//head->next = tail;
	count = 0;
	for (int i = 0; i < 2; i++)
	{
		RouteItem* temp = new RouteItem;
		temp->dst_net = (inet_addr(ip[i])) & (inet_addr(mask[i]));
		temp->mask = inet_addr(mask[i]);
		temp->type = 0;
		this->insert(temp);
	}
}

void RouteTable::remove(int index)
{
	for (RouteItem* t = head; t->next != tail; t = t->next)
	{
		if (t->next->index == index)
		{
			if (t->next->type == 0)
			{
				printf("该项不可删除！\n");
				return;
			}
			else
			{
				t->next = t->next->next;
				count--;
				return;
			}
		}
	}
	printf("查无此项，请重新输入！\n");
}


//查找路由表对应表项,并给出下一跳的ip地址
DWORD RouteTable::lookup(DWORD ip)
{
	RouteItem* t = head->next;
	for (; t != tail; t = t->next)
	{

		if ((t->mask & ip) == t->dst_net) {
			if (t->next_ip == 0) {
				return ip;
			}
			else
				return t->next_ip;
		}
	}
	return -1;
}

FILE* my_log::fp = nullptr;
my_log::my_log()
{
	fp = fopen("my_log.txt", "a+");
}
my_log::~my_log()
{
	fclose(fp);
}


void my_log::write_ip_log(const char* a, IPFrame_t* pkt)//ip类型
{
	fprintf(fp, a);
	fprintf(fp, "IP数据包-->");

	in_addr addr;
	addr.s_addr = pkt->IPHeader.SrcIP;
	char* str = inet_ntoa(addr);

	fprintf(fp, "源IP： ");
	fprintf(fp, "%s  ", str);
	fprintf(fp, "目的IP： ");
	addr.s_addr = pkt->IPHeader.DstIP;
	str = inet_ntoa(addr);
	fprintf(fp, "%s  ", str);
	fprintf(fp, "源MAC： ");
	for (int i = 0; i < 5; i++)
		fprintf(fp, "%02X-", pkt->FrameHeader.SrcMAC[i]);
	fprintf(fp, "%02X  ", pkt->FrameHeader.SrcMAC[5]);
	fprintf(fp, "目的MAC： ");
	for (int i = 0; i < 5; i++)
		fprintf(fp, "%02X-", pkt->FrameHeader.DesMAC[i]);
	fprintf(fp, "%02X\n", pkt->FrameHeader.DesMAC[5]);

}
void my_log::write_arp_log(const char* a, ARPFrame_t* pkt)//arp类型
{
	fprintf(fp, a);
	fprintf(fp, "ARP数据包-->");

	in_addr addr;
	addr.s_addr = pkt->SendIP;
	char* str = inet_ntoa(addr);
	fprintf(fp, "IP： ");
	fprintf(fp, "%s  ", str);

	fprintf(fp, "MAC： ");
	for (int i = 0; i < 5; i++)
		fprintf(fp, "%02X-", pkt->SendHa[i]);
	fprintf(fp, "%02X\n", pkt->SendHa[5]);

}
void my_log::write_arp_log(const char* a, ARPFrame_t pkt)//arp类型
{
	fprintf(fp, a);
	fprintf(fp, "ARP数据包-->");

	in_addr addr;
	addr.s_addr = pkt.SendIP;
	char* str = inet_ntoa(addr);
	fprintf(fp, "IP： ");
	fprintf(fp, "%s  ", str);

	fprintf(fp, "MAC： ");
	for (int i = 0; i < 5; i++)
		fprintf(fp, "%02X-", pkt.SendHa[i]);
	fprintf(fp, "%02X\n", pkt.SendHa[5]);

}
void my_log::write_icmp_log(const char* a)//icmp类型
{
	fprintf(fp, a);
}
//处理接收到的数据报的线程
DWORD WINAPI recv(LPVOID lparam)
{
	RouteTable router_table = *(RouteTable*)(LPVOID)lparam;//从参数中获取路由表
	struct bpf_program fcode;
	//编辑过滤字符串
	if (pcap_compile(choosed_dev, &fcode, "ip or arp", 1, bpf_u_int32(mask[0])) < 0)
	{
		fprintf(stderr, "\nError compiling filter: wrong syntax.\n");
		system("pause");
		return -1;
	}

	//绑定过滤器
	if (pcap_setfilter(choosed_dev, &fcode) < 0)
	{
		fprintf(stderr, "\nError setting the filter\n");
		system("pause");
		return -1;
	}
	while (1)
	{
		pcap_pkthdr* pkt_header;
		const u_char* pkt_data;
		while (1)
		{
			int ret = pcap_next_ex(choosed_dev, &pkt_header, &pkt_data);
			if (ret)break;
		}
		FrameHeader_t* header = (FrameHeader_t*)pkt_data;//格式化收到的包为帧首部，以获取目的MAC地址和帧类型
		if (Compare(header->DesMAC, my_mac))//只处理目的mac是自己的包
		{
			if (ntohs(header->FrameType) == 0x806)//收到ARP数据报
			{
				ARPFrame_t* data = (ARPFrame_t*)pkt_data;//格式化收到的包为帧首部+ARP首部类型
				my_log.write_arp_log("接收", data);
				//收到ARP响应包
				if (data->Operation == ntohs(0x0002)) {
					BYTE tmp_mac[6];
					if (ip_mac_table->lookup(data->SendIP, tmp_mac)) {//该映射关系已经存到路由表中，不做处理
					}
					else {

						DWORD tmp_ip;
						for (int i = 0; i < 6; i++) {
							tmp_mac[i] = data->SendHa[i];
						}
						tmp_ip = data->SendIP;
						ip_mac_table->insert(data->SendIP, data->SendHa);
					}
					//遍历缓冲区，看是否有可以转发的包
					for (int i = 0; i < totalcount; i++)
					{
						SendPacket_t packet = my_Buffer[i];
						if (packet.flag == 0)continue;
						if (clock() - packet.t >= 6000) {//超时
							packet.flag = 0;
							continue;
						}
						if (packet.TargetIP == data->SendIP)
						{
							IPFrame_t* IPf = (IPFrame_t*)packet.PktData;
							for (int i = 0; i < 6; i++) {
								IPf->FrameHeader.DesMAC[i] = data->SendHa[i];
							}

							for (int t = 0; t < 6; t++)
							{
								IPf->FrameHeader.SrcMAC[t] = my_mac[t];
							}
							// 发送IP数据包
							pcap_sendpacket(choosed_dev, (u_char*)packet.PktData, packet.len) != 0;
							my_Buffer->flag = 0;
							my_log.write_ip_log("转发", (IPFrame_t*)packet.PktData);
						}
					}

				}
			}
			else if (ntohs(header->FrameType) == 0x800)//收到IP数据报
			{
				IPFrame_t* data = (IPFrame_t*)pkt_data;//格式化收到的包为帧首部+IP首部类型
				my_log.write_ip_log("接收", data);
				//获取目的IP地址并在路由表中查找，并获取下一跳ip地址
				DWORD dst_ip = data->IPHeader.DstIP;
				DWORD next_ip = router_table.lookup(dst_ip);

				// ICMP超时
				if (data->IPHeader.TTL <= 0)
				{
					ICMPPacketProc(11, 0, pkt_data);
					continue;
				}
				IPHeader_t* IpHeader = &(data->IPHeader);
				// 差错
				if (test_checksum((char*)IpHeader) == 0)
				{
					my_log.write_ip_log("校验和错误，丢弃", data);
					continue;
				}
				if (next_ip == -1)
				{
					ICMPPacketProc(3, 0, pkt_data);// ICMP目的不可达
					continue;
				}
				else
				{
					SendPacket_t packet;
					packet.TargetIP = next_ip;

					for (int t = 0; t < 6; t++)
					{
						data->FrameHeader.SrcMAC[t] = my_mac[t];
					}
					data->IPHeader.TTL -= 1;// TTL减1

					unsigned short check_buff[sizeof(IPHeader_t)];
					// 设IP头中的校验和为0
					data->IPHeader.Checksum = 0;

					memset(check_buff, 0, sizeof(IPHeader_t));
					IPHeader_t* ip_header = &(data->IPHeader);
					memcpy(check_buff, ip_header, sizeof(IPHeader_t));

					// 计算IP头部校验和
					data->IPHeader.Checksum = cal_checksum(check_buff, sizeof(IPHeader_t));

					// IP-MAC地址映射表中存在该映射关系
					if (ip_mac_table->lookup(packet.TargetIP, data->FrameHeader.DesMAC))
					{
						memcpy(packet.PktData, pkt_data, pkt_header->len);
						packet.len = pkt_header->len;
						if (pcap_sendpacket(choosed_dev, (u_char*)packet.PktData, packet.len) != 0)
						{
							// 错误处理
							continue;
						}
						my_log.write_ip_log("转发", (IPFrame_t*)packet.PktData);
					}
					// IP-MAC地址映射表中不存在该映射关系
					else
					{
						if (totalcount < 50)		// 存入缓存队列
						{
							packet.len = pkt_header->len;
							// 将需要转发的数据报存入缓存区
							memcpy(packet.PktData, pkt_data, pkt_header->len);
							my_Buffer[totalcount++] = packet;
							packet.t = clock();
							my_log.write_ip_log("缓存", data);
							// 发送ARP请求
							get_mac_of(packet.TargetIP);
						}
						else
						{
							my_log.write_ip_log("缓冲区溢出，丢弃", data);
						}
					}
				}
			}
		}
	}
}

int arptable::num = 0;
void arptable::insert(DWORD ip, BYTE mac[6])
{
	ip_mac_table[num].ip = ip;
	memcpy(ip_mac_table[num].mac, mac, 6);
	num++;
}
int arptable::lookup(DWORD ip, BYTE mac[6])
{
	memset(mac, 0, 6);
	for (int i = 0; i < num; i++)
	{
		if (ip == ip_mac_table[i].ip)
		{
			memcpy(mac, ip_mac_table[i].mac, 6);
			return 1;
		}
	}
	return 0;
}
// 发送ICMP数据包
void ICMPPacketProc(BYTE type, BYTE code, const u_char* pkt_data)
{
	u_char* Buffer = new u_char[70];

	// 填充帧首部
	memcpy(((FrameHeader_t*)Buffer)->DesMAC, ((FrameHeader_t*)pkt_data)->SrcMAC, 6);
	memcpy(((FrameHeader_t*)Buffer)->SrcMAC, ((FrameHeader_t*)pkt_data)->DesMAC, 6);
	((FrameHeader_t*)Buffer)->FrameType = htons(0x0800);

	// 填充IP首部
	((IPHeader_t*)(Buffer + 14))->Ver_HLen = ((IPHeader_t*)(pkt_data + 14))->Ver_HLen;
	((IPHeader_t*)(Buffer + 14))->TOS = ((IPHeader_t*)(pkt_data + 14))->TOS;
	((IPHeader_t*)(Buffer + 14))->TotalLen = htons(56);
	((IPHeader_t*)(Buffer + 14))->ID = ((IPHeader_t*)(pkt_data + 14))->ID;
	((IPHeader_t*)(Buffer + 14))->Flag_Segment = ((IPHeader_t*)(pkt_data + 14))->Flag_Segment;
	((IPHeader_t*)(Buffer + 14))->TTL = 64;
	((IPHeader_t*)(Buffer + 14))->Protocol = 1;
	((IPHeader_t*)(Buffer + 14))->SrcIP = ((IPHeader_t*)(pkt_data + 14))->DstIP;
	((IPHeader_t*)(Buffer + 14))->DstIP = ((IPHeader_t*)(pkt_data + 14))->SrcIP;
	((IPHeader_t*)(Buffer + 14))->Checksum = htons(cal_checksum((unsigned short*)(Buffer + 14), 20));

	// 填充ICMP首部
	((ICMPHeader_t*)(Buffer + 34))->Type = type;
	((ICMPHeader_t*)(Buffer + 34))->Code = code;
	((ICMPHeader_t*)(Buffer + 34))->Id = 0;
	((ICMPHeader_t*)(Buffer + 34))->Sequence = 0;
	((ICMPHeader_t*)(Buffer + 34))->Checksum = htons(cal_checksum((unsigned short*)(Buffer + 34), 8));

	memcpy((u_char*)(Buffer + 42), (IPHeader_t*)(pkt_data + 14), 20);
	memcpy((u_char*)(Buffer + 62), (u_char*)(pkt_data + 34), 8);
	pcap_sendpacket(choosed_dev, (u_char*)Buffer, 70);

	if (type == 11)
	{
		my_log.write_icmp_log("发送ICMP超时数据包-->\n");
	}
	if (type == 3)
	{
		my_log.write_icmp_log("发送ICMP目的不可达数据包-->\n");
	}

	delete[] Buffer;
}
// 判断IP数据包头部校验和是否正确
int test_checksum(char* buffer)
{
	// 获得IP头内容
	IPHeader_t* ip_header = (IPHeader_t*)buffer;
	// 备份原来的校验和
	unsigned short checksumBuf = ip_header->Checksum;
	unsigned short check_buff[sizeof(IPHeader_t)];
	// 设IP头中的校验和为0
	ip_header->Checksum = 0;

	memset(check_buff, 0, sizeof(IPHeader_t));
	memcpy(check_buff, ip_header, sizeof(IPHeader_t));

	// 计算IP头部校验和
	ip_header->Checksum = cal_checksum(check_buff, sizeof(IPHeader_t));

	// 与备份的校验和进行比较
	if (ip_header->Checksum == checksumBuf)
	{
		return 1;
	}
	else
	{
		return 0;
	}
}
// 计算校验和
unsigned short cal_checksum(unsigned short* buffer, int size)
{
	// 32位，延迟进位
	unsigned long cksum = 0;
	while (size > 1)
	{
		cksum += *buffer++;
		// 16位相加
		size -= sizeof(unsigned short);
	}
	if (size)
	{
		// 最后可能有单独8位
		cksum += *(unsigned char*)buffer;
	}
	// 将高16位进位加至低16位
	cksum = (cksum >> 16) + (cksum & 0xffff);
	cksum += (cksum >> 16);
	// 取反
	return (unsigned short)(~cksum);
}