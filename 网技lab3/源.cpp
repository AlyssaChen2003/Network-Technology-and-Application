#define WIN32
#define WPCAP
#define HAVE_REMOTE
#include "pcap.h" 
#include <iostream>
#include <WinSock2.h>
#include <bitset>
#include <process.h>
#define ulong ULONG 
#define uint UINT 
using namespace std;
#pragma comment(lib,"wpcap.lib")
#pragma comment(lib,"ws2_32.lib")
#pragma warning(disable:4996)
void arp_protool_packet(struct pcap_pkthdr* header, const u_char* pkt_data);
void* get_in_addr(struct sockaddr* sa)
{
	if (sa->sa_family == AF_INET)
		return &(((struct sockaddr_in*)sa)->sin_addr);
	return &(((struct sockaddr_in6*)sa)->sin6_addr);
}
unsigned char mac[48], desmac[48];
pcap_t* targetDevice;
#pragma pack(1)
#define BYTE unsigned char
typedef struct FrameHeader_t {
	BYTE DesMAC[6];
	BYTE SrcMAC[6];
	WORD FrameType;
}FrameHeader_t;
typedef struct ARPFrame_t { //ARP帧
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
#pragma pack()
ARPFrame_t ARPFrame;
ARPFrame_t ARPFrame1;
//将Byte类型转化为十六进制字符串以便与主机信息进行验证
string* ByteToHexStr(unsigned char byte_arr[], int arr_len)
{
	string* hexstr = new string();
	for (int i = 0; i < arr_len; i++)
	{
		char hex_1;
		char hex_2;
		int value = byte_arr[i];
		int x = value / 16;
		int y = value % 16;
		if (x >= 0 && x <= 9)
			hex_1 = (char)(48 + x);
		else
			hex_1 = (char)(55 + x);
		if (y >= 0 && y <= 9)
			hex_2 = (char)(48 + y);
		else
			hex_2 = (char)(55 + y);
		if (i != arr_len - 1) {
			*hexstr = *hexstr + hex_1 + hex_2 + "-";
		}
		else
			*hexstr = *hexstr + hex_1 + hex_2;
	}
	return hexstr;
}
string GetIp(unsigned long u) {
	in_addr addr;
	memcpy(&addr, &u, sizeof(u));
	return inet_ntoa(addr);//将in_addr结构转化为IP的点数格式
}
void arp_protool_packet(struct pcap_pkthdr* header, const u_char* pkt_data)
{
	struct ARPFrame_t* arp_protocol;
	arp_protocol = (struct ARPFrame_t*)(pkt_data);
	unsigned char* arp_sha = arp_protocol->SendHa;
	unsigned char* arp_tha = arp_protocol->RecvHa;
	cout << "操作类型:" << ntohs(arp_protocol->Operation) << endl;
	cout << "源 MAC 地址： " << *(ByteToHexStr(arp_protocol->FrameHeader.SrcMAC, 6)) <<endl;
	cout << "源 IP 地址： " << GetIp(arp_protocol->SendIP) << endl;
	cout << "目的 MAC 地址:" << *(ByteToHexStr(arp_protocol->FrameHeader.DesMAC, 6)) <<endl;
	cout << "目的 IP 地址 " << GetIp(arp_protocol->RecvIP) << endl;
	cout << endl;
}
/*实验3的检查需要验证程序输出的若干IP与MAC的正确性，下面有三个备选方案，同学们做实验时可以参考：
a.电脑连接手机热点，提前查明电脑和手机的IP和MAC
b.两台电脑连接同一个热点，提前查明两台电脑的IP和MAC
c.电脑连接校园网，在电脑cmd中提前查明本机的IP和MAC、本机的ARP映射表中的IP和MAC*/
int main() {
	pcap_if_t* allDevices, * currentDevice;
	pcap_addr_t* a;
	int i = 0;
	char errbuf[PCAP_ERRBUF_SIZE];
	if (pcap_findalldevs(&allDevices, errbuf) == -1)
	{
		cout << stderr << "寻找设备错误" << errbuf << endl;
		return 0;
	}
	for (currentDevice = allDevices; currentDevice; currentDevice = currentDevice->next)
	{
		cout << ++i << ". " << currentDevice->name;
		if (currentDevice->description)
			cout << "(" << currentDevice->description << ")" << endl;
		else
			cout << "(无可用描述)\n";
		for (a = currentDevice->addresses; a != NULL; a = a->next) {
			if (a->addr->sa_family == AF_INET) {
				cout << "=============================================================================== \n\n";
				char str[INET_ADDRSTRLEN];
				inet_ntop(AF_INET, get_in_addr((struct sockaddr*)a->addr), str, sizeof(str));
				cout << "IP 地址:" << str << endl;
				inet_ntop(AF_INET, get_in_addr((struct sockaddr*)a->netmask), str, sizeof(str));
				cout << "网络掩码:" << str << endl;
				inet_ntop(AF_INET, get_in_addr((struct sockaddr*)a->broadaddr), str, sizeof(str));
				cout << "广播地址:" << str << endl;

			}
		}
	}
	if (i == 0)
	{
		cout << "\n 未找到接口；请确认WinPcap已安装！\n";
		return 0;
	}
	cout <<"=============================================================================== \n\n";
	currentDevice = allDevices;
	int j;
	cout << "请选择发送数据包的网卡：";
	cin >> j;
	for (i = 0; i < j - 1; i++) {
		currentDevice = currentDevice->next;
	}
	char ip[INET_ADDRSTRLEN];
	for (a = currentDevice->addresses; a != NULL; a = a->next) {
		if (a->addr->sa_family == AF_INET) {
			inet_ntop(AF_INET, get_in_addr((struct sockaddr*)a->addr), ip, sizeof(ip));
		}
	}
	cout << ip;
	cout << endl << currentDevice->name << endl;
	targetDevice = pcap_open(currentDevice->name, 100, PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL, errbuf);
	if (targetDevice == NULL) {
		cout << "打开设备错误 " << errbuf << endl;
		pcap_freealldevs(allDevices);
		return 0;
	}
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
	ARPFrame1.RecvIP = inet_addr(ip);
	struct pcap_pkthdr* pkt_header;
	const u_char* pkt_data;
	struct pcap_pkthdr* header = new pcap_pkthdr;
	int k;
	while ((k = pcap_next_ex(targetDevice, &pkt_header, &pkt_data)) >= 0) {
		pcap_sendpacket(targetDevice, (u_char*)&ARPFrame1, sizeof(ARPFrame_t));	
		if (k == 0)continue;
		else if (*(unsigned short*)(pkt_data + 12) == htons(0x0806) && *(unsigned
			short*)(pkt_data + 20) == htons(0x0002)
			&& *(unsigned long*)(pkt_data + 28) == ARPFrame1.RecvIP) {
			cout << "ARP 数据包中主要内容：\n";
			arp_protool_packet(header, pkt_data);
			for (int i = 0; i < 6; i++) {
				mac[i] = *(unsigned char*)(pkt_data + 22 + i);
			}
			cout << "获取自己主机的 MAC 地址成功，本机 MAC 地址为：" <<
				*(ByteToHexStr(mac, 6)) << endl;
			break;
		}
	}
	if (k < 0) {
		cout << "Error in pcap_next_ex." << endl;
	}
	cout <<"=============================================================================== \n\n";
	for (int i = 0; i < 6; i++) {	
		ARPFrame.FrameHeader.DesMAC[i] = 0xff;		//设置为广播地址
		ARPFrame.RecvHa[i] = 0x00;					//设置为0
		ARPFrame.FrameHeader.SrcMAC[i] = mac[i];	//设置为本机的mac地址
		ARPFrame.SendHa[i] = mac[i];				//设置为本机的mac地址
	}
	ARPFrame.FrameHeader.FrameType = htons(0x0806);		//帧类型为ARP
	ARPFrame.HardwareType = htons(0x0001);				//硬件类型为以太网
	ARPFrame.ProtocolType = htons(0x0800);				//协议类型为IP
	ARPFrame.HLen = 6;									//硬件地址为6
	ARPFrame.PLen = 4;									//协议地址长度为4
	ARPFrame.Operation = htons(0x0001);					//操作为ARP请求
	ARPFrame.SendIP = inet_addr(ip);					//设置为本机网卡上绑定的ip地址
	cout << "请输入目的主机的 IP 地址:";
	char s[INET_ADDRSTRLEN];
	cin >> s;
	ARPFrame.RecvIP = inet_addr(s);						//设置为请求的ip地址
	while ((k = pcap_next_ex(targetDevice, &pkt_header, &pkt_data)) >= 0) {
		//进行数据包捕获
		pcap_sendpacket(targetDevice, (u_char*)&ARPFrame, sizeof(ARPFrame_t));
		
		
	if (i == 0)continue;
	else if (*(unsigned short*)(pkt_data + 12) == htons(0x0806)
		&& *(unsigned short*)(pkt_data + 20) == htons(0x0002)
		&& *(unsigned long*)(pkt_data + 28) == ARPFrame.RecvIP) {
		cout << "ARP 数据包主要内容\n";
		arp_protool_packet(header, pkt_data);
		for (int i = 0; i < 6; i++) {
			desmac[i] = *(unsigned char*)(pkt_data + 22 + i);
		}
		cout << "获取目的主机的 MAC 地址成功，目的主机的 MAC 地址为：" <<
			*(ByteToHexStr(desmac, 6)) << endl;
		break;
	}
		
	}
	pcap_freealldevs(allDevices);
	//system("pause");
}



