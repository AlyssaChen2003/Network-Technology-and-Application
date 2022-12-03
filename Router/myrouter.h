#ifndef MYROUTER_H//�������ͷ�ļ�
#define MYROUTER_H
#define WIN32
#define WPCAP
#define HAVE_REMOTE
#include "pcap.h"
//#include <iostream>
#include<WinSock2.h>
#include <process.h>
#include <stdio.h>
#include <bitset>
#include <time.h>
#pragma comment(lib,"wpcap.lib")
//#pragma comment(lib, "packet.lib")
#pragma comment(lib,"ws2_32.lib")
#pragma warning(disable:4996)
#define _CRT_SECURE_NO_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define BYTE unsigned char

using namespace std;



#pragma pack(1) //һ�ֽڶ���
/************************************struct�������ݽṹ*****************************************/
typedef struct FrameHeader_t {//��̫������֡�ײ�
    BYTE DesMAC[6];
    BYTE SrcMAC[6];
    WORD FrameType;
} FrameHeader_t;

typedef struct IPHeader_t {//����IP�ײ�
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
} IPHeader_t;

typedef struct IPFrame_t {//����֡�ײ���IP�ײ������ݰ�
    FrameHeader_t FrameHeader;
    IPHeader_t IPHeader;
} IPFrame_t;

typedef struct ICMPHeader_t {
    BYTE Type;
    BYTE Code;
    WORD cksum;
    WORD Id;
    WORD Seq;
} ICMPHeader_t;

typedef struct ARPFrame_t { //ARP֡
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
} ARPFrame_t;



/*******************************ȫ�ֱ���(1)**************************************/

pcap_if_t* allDevices;
pcap_if_t* currentDevice;
pcap_t* targetDevice;
pcap_if_t* net[10];
char ip[10][20];
char mask[10][20];
BYTE my_mac[6];
HANDLE hThread;
DWORD dwThreadId;



/************************************·�ɱ���******************************************/
class route_entry {
public:
	route_entry* next; //�������һ��
	int index; //�ñ��������
	DWORD netmask; //����
	DWORD dstNet; //Ŀ������
	DWORD nextHop; //��һ������IP��
	BYTE nextMAC[6]; //��һ����MAC
	bool type; //�������ͣ�falseΪ����ɾ����trueΪ�û���ӣ���ɾ��
	route_entry() {
		memset(this, 0, sizeof(*this));

	}
	void setRoute(){}
	void print() { //��ӡ��·�ɱ���
		in_addr addr;
		printf("[%d]   ", index+1);
		addr.s_addr = netmask;
		char* str = inet_ntoa(addr);
		printf("%*s", 18,str);

		addr.s_addr = dstNet;
		str = inet_ntoa(addr);
		printf("%*s", 18, str);

		addr.s_addr = nextHop;
		str = inet_ntoa(addr);
		printf("%*s", 18, str);

		printf("%*d\n",5, type);
	}
};


/************************************·�ɱ�******************************************/
class RouteTable {
public:
	route_entry* head,* tail;
	int count;
	RouteTable() {
		head = new route_entry;
		head->next = NULL;
		count = 0;
		for (int i = 0; i < 2; i++) {
			route_entry* r = new route_entry;
			r->dstNet = (inet_addr(ip[i])) & (inet_addr(mask[i]));
			r->netmask = inet_addr(mask[i]);
			r->type = 0;
			this->insert(r);
		}
	}
	void insert(route_entry* r) { //�������뽵������
		route_entry* p;
		if (this->count == 0) {
			head->next = r;
			r->next = NULL;

		}
		else {
			p = head->next;
			while (p != NULL) {
				if (p->next == NULL || (r->netmask < p->netmask && r->netmask >= p->next->netmask)) {
					break;
				}
				p = p->next;
			}
			if (p->next == NULL) { //���p�ҵ��˵�ǰ·�ɱ�����һ���r��������С������r��Ϊ·�ɱ�����һ��
				r->next = NULL;
				p->next = r;

			}
			else { //������p����
				r->next = p->next;
				p->next = r;

			}
		}
		p = head->next;
		for (int i = 0; p; i++) {
			p->index = i;
			p = p->next;
		}
		count++;
		printf("[INSERT] OK! \n");
		//cout << "[INSERT] OK!" << endl;
	}
	void remove(int x) {//ɾ������Ϊx�ı���
		for (route_entry* p = head; p; p = p->next) {
			if (x == 0) {
				if (head->type) {
					route_entry* q = head->next;
					head = q;
					head->next = q->next;
					count--;
					printf("[DELETE] No.[%d] route entry----OK!\n", x + 1);
					//cout << "[DELETE] No.[" << x << "] route entry----OK! " << endl;
					route_entry* temp = head->next;
					//��������
					for (int i = 0; temp; i++) {
						temp->index = i;
						temp = temp->next;
					}
					return;
				}
				else {
					printf("[DELETE] No.[%d] route entry----can't be deleted!\n", x + 1);
					//cout << "[DELETE] No.[" << x << "] route entry----can't be deleted! " << endl;
					return;
				}
			}
			if (p->index == x-1) { //�ҵ���Ҫɾ���ı����ǰһ��
				if (p->next->type) {
					route_entry* q = p->next;
					p->next = q->next;
					count--;
					printf("[DELETE] No.[%d] route entry----OK!\n", x+1);
					route_entry* temp = head->next;
					//��������
					for (int i = 0; temp; i++) {
						temp->index = i;
						temp = temp->next;
					}
					//cout << "[DELETE] No.[" << x << "] route entry----OK! " << endl;
					return;
				}
				else {
					printf("[DELETE] No.[%d] route entry----can't be deleted!\n", x+1);
					//cout << "[DELETE] No.[" << x << "] route entry----can't be deleted! " << endl;
					return;
				}
			}
			
		}
		printf("[DELETE] No.[%d] route entry----can't be found!\n", x);
		//cout << "[DELETE] No.[" << x << "] route entry----can't be found" << endl;
	}

	DWORD find(DWORD ip) { //���ݸ�������·�ɱ��Ӧ�������nextHop
		route_entry* p = head;
		while (p) {
			if ((p->netmask & ip) == p->dstNet) {
				if (p->nextHop)
					return p->nextHop;
				else
					return ip;
			}
			p = p->next;
		}
		return -1;

	}
	void printTable() { //��ӡ·�ɱ�
		route_entry* p = head->next;
		printf("****************************Route Table ********************************\n");
		printf("index");
		printf("%*s", 19,"NetMask");
		printf("%*s", 18, "DstNet");
		printf("%*s", 18, "NextHFop");
		printf("%*s \n", 5, "type");
		//cout << "**********************************************Route Table *********************************************" << endl;
		while (p) {
			p->print();
			p = p->next;
		}
		printf("*************************************************************************\n");
		//cout << "*****************************************************************************************************" << endl;

	}


};

#pragma pack() //�ָ�4�ֽڶ���
typedef struct sndPkt_t { //���͵����ݰ�
	int len;
	BYTE pktData[2000];
	u_long targetIP;
	bool flag = 1; //�Ƿ���Ч��1Ϊ��Ч
	clock_t t;
		
} sndPkt_t;

sndPkt_t databuf[50];		//�������ݰ��Ļ�������
clock_t times[50];		//�������б��ĵĴ��ʱ��
int packetnum = 0;		//�������з������ݰ�����

/****************************************ARP��************************************************/
class arptable {
public:
	DWORD ip;
	BYTE mac[6];
	static int num;

	static void insert(DWORD ip, BYTE mac[6]);
	static int find(DWORD ip, BYTE mac[6]);

}ip_mac_table[50];

int arptable::num = 0;
void arptable::insert(DWORD ip, BYTE mac[6]){
	ip_mac_table[num].ip = ip;
	memcpy(ip_mac_table[num].mac, mac, 6);
	num++;
}
int arptable::find(DWORD ip, BYTE mac[6]){
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


/*****************************************��־��***************************************************/
class my_log{
public:
	my_log();
	~my_log();

	static FILE* fp;
	//д����־

	static void write_arp_log(const char* a, ARPFrame_t);//arp����
	static void write_arp_log(const char* a, ARPFrame_t* pkt);
	static void write_ip_log(const char* a, IPFrame_t*);//ip����
	static void write_icmp_log(const char* a);//icmp����
}my_log;

FILE* my_log::fp = nullptr;
my_log::my_log(){
	fp = fopen("my_log.txt", "a+");
}
my_log::~my_log(){
	fclose(fp);
}


void my_log::write_ip_log(const char* a, IPFrame_t* pkt){//ip����
	fprintf(fp, a);
	fprintf(fp, "IP Packet-->");

	in_addr addr;
	addr.s_addr = pkt->IPHeader.SrcIP;
	char* str = inet_ntoa(addr);

	fprintf(fp, "SrcIP�� ");
	fprintf(fp, "%s  ", str);
	fprintf(fp, "DstIP�� ");
	addr.s_addr = pkt->IPHeader.DstIP;
	str = inet_ntoa(addr);
	fprintf(fp, "%s  ", str);
	fprintf(fp, "SrcMAC�� ");
	for (int i = 0; i < 5; i++)
		fprintf(fp, "%02X-", pkt->FrameHeader.SrcMAC[i]);
	fprintf(fp, "%02X  ", pkt->FrameHeader.SrcMAC[5]);
	fprintf(fp, "DstMAC�� ");
	for (int i = 0; i < 5; i++)
		fprintf(fp, "%02X-", pkt->FrameHeader.DesMAC[i]);
	fprintf(fp, "%02X\n", pkt->FrameHeader.DesMAC[5]);

}
void my_log::write_arp_log(const char* a, ARPFrame_t *pkt) {	//arp����

	fprintf(fp, a);
	fprintf(fp, "ARP Packet-->");

	in_addr addr;
	addr.s_addr = pkt->SendIP;
	char* str = inet_ntoa(addr);
	fprintf(fp, "IP�� ");
	fprintf(fp, "%s  ", str);

	fprintf(fp, "MAC�� ");
	for (int i = 0; i < 5; i++)
		fprintf(fp, "%02X-", pkt->SendHa[i]);
	fprintf(fp, "%02X\n", pkt->SendHa[5]);

}
void my_log::write_arp_log(const char* a, ARPFrame_t pkt){	//arp����

	fprintf(fp, a);
	fprintf(fp, "ARP Packet-->");

	in_addr addr;
	addr.s_addr = pkt.SendIP;
	char* str = inet_ntoa(addr);
	fprintf(fp, "IP�� ");
	fprintf(fp, "%s  ", str);

	fprintf(fp, "MAC�� ");
	for (int i = 0; i < 5; i++)
		fprintf(fp, "%02X-", pkt.SendHa[i]);
	fprintf(fp, "%02X\n", pkt.SendHa[5]);

}
void my_log::write_icmp_log(const char* a){		//icmp����

	fprintf(fp, a);
}


/*******************************************������Ҫ�õĺ���*******************************************************/

void getLocalIP();
void getLocalMac(DWORD ip);
bool Compare(BYTE x[6], BYTE y[6]);
void print_mac(BYTE mac[]);
void ICMPPacketProc(BYTE type, BYTE code, const u_char* pkt_data);
int test_checksum(char* buffer);
unsigned short cal_checksum(unsigned short* buffer, int size);
DWORD WINAPI recv(LPVOID lparam);

void getLocalIP() {
	int i = 0;
	pcap_addr_t* a;
	char errbuf[PCAP_ERRBUF_SIZE];
	if (pcap_findalldevs(&allDevices, errbuf) == -1)
	{
		printf("%serror in finding devices....%s\n", stderr, errbuf);
		//cout << stderr << "error in finding devices...." << errbuf << endl;
		//return 0;
	}
	for (currentDevice = allDevices; currentDevice; currentDevice = currentDevice->next)
	{
		printf("%d.%s\n", ++i, currentDevice->name);
		//cout << ++i << ". " << currentDevice->name;
		if (currentDevice->description)
			printf("(%s)\n",currentDevice->description);
			//cout << "(" << currentDevice->description << ")" << endl;
		else
			printf("no description available\n");
			//cout << "(no description available)\n";
		for (a = currentDevice->addresses; a != NULL; a = a->next) {
			if (a->addr->sa_family == AF_INET) {
				printf("\n*******************************************************\n");
				//cout << "=============================================================================== \n\n";
				char str[INET_ADDRSTRLEN];
				strcpy(str, inet_ntoa(((struct sockaddr_in*)a->addr)->sin_addr));
				printf("IP Address��%s\n", str);
				strcpy(str, inet_ntoa(((struct sockaddr_in*)a->netmask)->sin_addr));
				printf("Net Mask��%s\n", str);
				strcpy(str, inet_ntoa(((struct sockaddr_in*)a->broadaddr)->sin_addr));
				printf("Broadcast Address��%s\n", str);

			}
		}
	}
	if (i == 0)
	{
		printf("no interfaces detected; make sure wincap is installed!\n");
		//cout << "\n no interfaces detected; make sure wincap is installed! \n";
		//return 0;
	}
	currentDevice = allDevices;
	int j;
	printf("***************Please Choose Target Device********************** \n\n");
	//cout << "********************************Please Choose Target Device************************************* \n\n";
	scanf("%d", &j);
	for (i = 0; i < j - 1; i++) {
		currentDevice = currentDevice->next;
	}
	int k = 0;
	//char ip[INET_ADDRSTRLEN];
	for (a = currentDevice->addresses; a != NULL; a = a->next) {
		if (a->addr->sa_family == AF_INET) {
			//inet_ntop(AF_INET, get_in_addr((struct sockaddr*)a->addr), ip, sizeof(ip));
			strcpy(ip[k], inet_ntoa(((struct sockaddr_in*)a->addr)->sin_addr));
			strcpy(mask[k++], inet_ntoa(((struct sockaddr_in*)a->netmask)->sin_addr));

		}
	}
	//printf("%x", ip);
	////cout << ip;
	//printf("%s \n", currentDevice->name);
	//cout << endl << currentDevice->name << endl;
	targetDevice = pcap_open(currentDevice->name, 100, PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL, errbuf);
	if (targetDevice == NULL) {
		printf("error in opening device %s \n", errbuf);
		//cout << "error in opening device " << errbuf << endl;
		
		//return 0;
	}
	pcap_freealldevs(allDevices);
}
void getLocalMac(DWORD ip) { //��ȡ������mac��ַ
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
	while ((k = pcap_next_ex(targetDevice, &pkt_header, &pkt_data)) >= 0) {
		pcap_sendpacket(targetDevice, (u_char*)&ARPFrame1, sizeof(ARPFrame_t));
		if (k == 0)
			continue;
		else if (*(unsigned short*)(pkt_data + 12) == htons(0x0806) && *(unsigned short*)(pkt_data + 20) == htons(0x0002)&& *(unsigned long*)(pkt_data + 28) == ARPFrame1.RecvIP) {
			//cout << "ARP ���ݰ�����Ҫ���ݣ�\n";
			//arp_protool_packet(header, pkt_data);
			for (int i = 0; i < 6; i++) {
				my_mac[i] = *(unsigned char*)(pkt_data + 22 + i);
			}
			/*cout << "��ȡ�Լ������� MAC ��ַ�ɹ������� MAC ��ַΪ��" <<
				*(ByteToHexStr(mac, 6)) << endl;*/
			break;
		}
	}
}
void get_mac_of(DWORD ip_)//��ȡip��Ӧ��mac
{
	ARPFrame_t ARPFrame;
	//��APRFrame.FrameHeader.DesMAC����Ϊ�㲥��ַ
	for (int i = 0; i < 6; i++)
		ARPFrame.FrameHeader.DesMAC[i] = 0xff;
	//��APRFrame.FrameHeader.SrcMAC����Ϊ����������MAC��ַ
	for (int i = 0; i < 6; i++)
	{
		ARPFrame.FrameHeader.SrcMAC[i] = my_mac[i];
		ARPFrame.SendHa[i] = my_mac[i];
	}
	ARPFrame.FrameHeader.FrameType = htons(0x806);//֡����ΪARP
	ARPFrame.HardwareType = htons(0x0001);//Ӳ������Ϊ��̫��
	ARPFrame.ProtocolType = htons(0x0800);//Э������ΪIP
	ARPFrame.HLen = 6;//Ӳ����ַ����Ϊ6
	ARPFrame.PLen = 4;//Э���ַ��Ϊ4
	ARPFrame.Operation = htons(0x0001);//����ΪARP����
	//��ARPFrame->SendIP����Ϊ���������ϰ󶨵�IP��ַ
	ARPFrame.SendIP = inet_addr(ip[0]);
	//��ARPFrame->RecvHa����Ϊ0
	for (int i = 0; i < 6; i++)
		ARPFrame.RecvHa[i] = 0;
	ARPFrame.RecvIP = ip_;

	pcap_sendpacket(targetDevice, (u_char*)&ARPFrame, sizeof(ARPFrame_t));
	my_log.write_arp_log("[SEND]", ARPFrame);
}
bool Compare(BYTE x[6], BYTE y[6]) { //�Ƚ�����mac��ַ�Ƿ���ͬ

	for (int i = 0; i < 6; i++) {
		if (x[i] != y[i])
			return false;
	}
	return true;
}

void print_mac(BYTE mac[]) {
	printf("MAC Address�� ");
	for (int i = 0; i < 6; i++) {
		if(i==5)
			printf("%2X\n", mac[i]);
		else
			printf("%2X-", mac[i]);

	}

}

void ICMPPacketProc(BYTE type, BYTE code, const u_char* pkt_data)
{
	u_char* Buffer = new u_char[70];

	// ���֡�ײ�
	memcpy(((FrameHeader_t*)Buffer)->DesMAC, ((FrameHeader_t*)pkt_data)->SrcMAC, 6);
	memcpy(((FrameHeader_t*)Buffer)->SrcMAC, ((FrameHeader_t*)pkt_data)->DesMAC, 6);
	((FrameHeader_t*)Buffer)->FrameType = htons(0x0800);

	// ���IP�ײ�
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

	// ���ICMP�ײ�
	((ICMPHeader_t*)(Buffer + 34))->Type = type;
	((ICMPHeader_t*)(Buffer + 34))->Code = code;
	((ICMPHeader_t*)(Buffer + 34))->Id = 0;
	((ICMPHeader_t*)(Buffer + 34))->Seq = 0;
	((ICMPHeader_t*)(Buffer + 34))->cksum = htons(cal_checksum((unsigned short*)(Buffer + 34), 8));

	memcpy((u_char*)(Buffer + 42), (IPHeader_t*)(pkt_data + 14), 20);
	memcpy((u_char*)(Buffer + 62), (u_char*)(pkt_data + 34), 8);
	pcap_sendpacket(targetDevice, (u_char*)Buffer, 70);

	if (type == 11)
	{
		my_log.write_icmp_log("[send ICMP TIMEOUT packet]-->\n");
	}
	if (type == 3)
	{
		my_log.write_icmp_log("[send ICMP UNREACHABLE packet]-->\n");
	}

	delete[] Buffer;
}
// �ж�IP���ݰ�ͷ��У����Ƿ���ȷ
int test_checksum(char* buffer)
{
	// ���IPͷ����
	IPHeader_t* ip_header = (IPHeader_t*)buffer;
	// ����ԭ����У���
	unsigned short checksumBuf = ip_header->Checksum;
	unsigned short check_buff[sizeof(IPHeader_t)];
	// ��IPͷ�е�У���Ϊ0
	ip_header->Checksum = 0;

	memset(check_buff, 0, sizeof(IPHeader_t));
	memcpy(check_buff, ip_header, sizeof(IPHeader_t));

	// ����IPͷ��У���
	ip_header->Checksum = cal_checksum(check_buff, sizeof(IPHeader_t));

	// �뱸�ݵ�У��ͽ��бȽ�
	if (ip_header->Checksum == checksumBuf)
	{
		return 1;
	}
	else
	{
		return 0;
	}
}
// ����У���
unsigned short cal_checksum(unsigned short* buffer, int size)
{
	// 32λ���ӳٽ�λ
	unsigned long cksum = 0;
	while (size > 1)
	{
		cksum += *buffer++;
		// 16λ���
		size -= sizeof(unsigned short);
	}
	if (size)
	{
		// �������е���8λ
		cksum += *(unsigned char*)buffer;
	}
	// ����16λ��λ������16λ
	cksum = (cksum >> 16) + (cksum & 0xffff);
	cksum += (cksum >> 16);
	// ȡ��
	return (unsigned short)(~cksum);
}

DWORD WINAPI recv(LPVOID lparam){
	RouteTable router_table = *(RouteTable*)(LPVOID)lparam;//�Ӳ����л�ȡ·�ɱ�
	struct bpf_program fcode;
	//�༭�����ַ���
	if (pcap_compile(targetDevice, &fcode, "ip or arp", 1, bpf_u_int32(mask[0])) < 0)
	{
		fprintf(stderr, "\nError compiling filter: wrong syntax.\n");
		system("pause");
		return -1;
	}

	//�󶨹�����
	if (pcap_setfilter(targetDevice, &fcode) < 0)
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
			int ret = pcap_next_ex(targetDevice, &pkt_header, &pkt_data);
			if (ret)break;
		}
		FrameHeader_t* header = (FrameHeader_t*)pkt_data;//��ʽ���յ��İ�Ϊ֡�ײ����Ի�ȡĿ��MAC��ַ��֡����
		if (Compare(header->DesMAC, my_mac))//ֻ����Ŀ��mac���Լ��İ�
		{
			if (ntohs(header->FrameType) == 0x806)//�յ�ARP���ݱ�
			{
				ARPFrame_t* data = (ARPFrame_t*)pkt_data;//��ʽ���յ��İ�Ϊ֡�ײ�+ARP�ײ�����
				my_log.write_arp_log("[RECV]", data);
				//�յ�ARP��Ӧ��
				if (data->Operation == ntohs(0x0002)) {
					BYTE tmp_mac[6];
					if (ip_mac_table->find(data->SendIP, tmp_mac));//��ӳ���ϵ�Ѿ��浽·�ɱ��У���������
					
					else {

						DWORD tmp_ip;
						for (int i = 0; i < 6; i++) {
							tmp_mac[i] = data->SendHa[i];
						}
						tmp_ip = data->SendIP;
						ip_mac_table->insert(data->SendIP, data->SendHa);
					}
					//���������������Ƿ��п���ת���İ�
					for (int i = 0; i < packetnum; i++)
					{
						sndPkt_t packet = databuf[i];
						if (packet.flag == 0)
							continue;
						if (clock() - packet.t >= 6000) {//��ʱ
							packet.flag = 0;
							continue;
						}
						if (packet.targetIP == data->SendIP)
						{
							IPFrame_t* IPf = (IPFrame_t*)packet.pktData;
							for (int i = 0; i < 6; i++) {
								IPf->FrameHeader.DesMAC[i] = data->SendHa[i];
							}

							for (int t = 0; t < 6; t++)
							{
								IPf->FrameHeader.SrcMAC[t] = my_mac[t];
							}
							// ����IP���ݰ�
							pcap_sendpacket(targetDevice, (u_char*)packet.pktData, packet.len) != 0;
							databuf->flag = 0;
							my_log.write_ip_log("[TRANSMIT]", (IPFrame_t*)packet.pktData);
						}
					}

				}
			}
			else if (ntohs(header->FrameType) == 0x800)//�յ�IP���ݱ�
			{
				IPFrame_t* data = (IPFrame_t*)pkt_data;//��ʽ���յ��İ�Ϊ֡�ײ�+IP�ײ�����
				my_log.write_ip_log("[RECV]", data);
				//��ȡĿ��IP��ַ����·�ɱ��в��ң�����ȡ��һ��ip��ַ
				DWORD dst_ip = data->IPHeader.DstIP;
				DWORD next_ip = router_table.find(dst_ip);

				// ICMP��ʱ
				if (data->IPHeader.TTL <= 0)
				{
					ICMPPacketProc(11, 0, pkt_data);
					continue;
				}
				IPHeader_t* IpHeader = &(data->IPHeader);
				// ���
				if (test_checksum((char*)IpHeader) == 0)
				{
					my_log.write_ip_log("[DUMPED----error in checksum]", data);
					continue;
				}
				if (next_ip == -1)
				{
					ICMPPacketProc(3, 0, pkt_data);// ICMPĿ�Ĳ��ɴ�
					continue;
				}
				else
				{
					sndPkt_t packet;
					packet.targetIP = next_ip;

					for (int t = 0; t < 6; t++)
					{
						data->FrameHeader.SrcMAC[t] = my_mac[t];
					}
					data->IPHeader.TTL -= 1;// TTL��1

					unsigned short check_buff[sizeof(IPHeader_t)];
					// ��IPͷ�е�У���Ϊ0
					data->IPHeader.Checksum = 0;

					memset(check_buff, 0, sizeof(IPHeader_t));
					IPHeader_t* ip_header = &(data->IPHeader);
					memcpy(check_buff, ip_header, sizeof(IPHeader_t));

					// ����IPͷ��У���
					data->IPHeader.Checksum = cal_checksum(check_buff, sizeof(IPHeader_t));

					// IP-MAC��ַӳ����д��ڸ�ӳ���ϵ
					if (ip_mac_table->find(packet.targetIP, data->FrameHeader.DesMAC))
					{
						memcpy(packet.pktData, pkt_data, pkt_header->len);
						packet.len = pkt_header->len;
						if (pcap_sendpacket(targetDevice, (u_char*)packet.pktData, packet.len) != 0)
						{
							// ������
							continue;
						}
						my_log.write_ip_log("[TRANSMIT]", (IPFrame_t*)packet.pktData);
					}
					// IP-MAC��ַӳ����в����ڸ�ӳ���ϵ
					else
					{
						if (packetnum < 50)		// ���뻺�����
						{
							packet.len = pkt_header->len;
							// ����Ҫת�������ݱ����뻺����
							memcpy(packet.pktData, pkt_data, pkt_header->len);
							databuf[packetnum++] = packet;
							packet.t = clock();
							my_log.write_ip_log("[SAVE IN BUFFER]", data);
							// ����ARP����
							get_mac_of(packet.targetIP);
						}
						else
						{
							my_log.write_ip_log("[DUMPED----buffer overflow]", data);
						}
					}
				}
			}
		}
	}
}




#endif
