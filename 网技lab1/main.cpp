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
pcap_t* targetDevice;
typedef struct FrameHeader_t {//��̫������֡�ײ�
    BYTE DesMAC[6];
    BYTE SrcMAC[6];
    WORD FrameType;
}FrameHeader_t;
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
}IPHeader_t;
typedef struct Data_t {//����֡�ײ���IP�ײ������ݰ�
    FrameHeader_t FrameHeader;
    IPHeader_t IPHeader;
}Data_t;
#pragma pack()
//��Byte����ת��Ϊʮ�������ַ����Ա���������Ϣ������֤
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
    return inet_ntoa(addr);//��in_addr�ṹת��ΪIP�ĵ�����ʽ
}
void WordToBitStr(WORD b) {
    cout << bitset<16>(b);
}
void captureIP(void* a) {
    struct pcap_pkthdr* pkt_header;
    const u_char* pkt_data;
    pkt_data = NULL;
    int i;
    int num = 1;
    for(i= pcap_next_ex(targetDevice, &pkt_header, &pkt_data);i>=0;){//�������ݰ�����
        if (i == 0)continue;
        else {
            Data_t* IPPacket;
            IPPacket = (Data_t*)pkt_data; //�����������벶�񵽵��������ݰ�
            cout << "��" << num << "�����ݰ���" << endl;
            cout << "ԴMAC��ַ��  " << *(ByteToHexStr(IPPacket->FrameHeader.SrcMAC, 6)) << endl;
            cout << "Ŀ��MAC��ַ��" << *(ByteToHexStr(IPPacket->FrameHeader.DesMAC, 6)) << endl;
            cout << "ԴIP��ַ��   " << GetIp(IPPacket->IPHeader.SrcIP) << endl;
            cout << "Ŀ��IP��ַ�� " << GetIp(IPPacket->IPHeader.DstIP) << endl;
            cout << "���ͣ�       " << IPPacket->FrameHeader.FrameType << endl;
            cout << "���ȣ�       " << IPPacket->IPHeader.TotalLen << endl;

            num++;
        }
        if (num == 5)break;
    }
    if (i < 0) {
        cout << "Error in pcap_next_ex." << endl;
    }
    _endthread();
}


int main() {
    pcap_if_t* allDevices, * currentDevice;
    int i = 0;
    char errbuf[PCAP_ERRBUF_SIZE];
    if (pcap_findalldevs(&allDevices, errbuf) == -1)
    {
        cout << stderr << "Ѱ���豸����" << errbuf << endl;
        return 0;
    }
    for (currentDevice = allDevices; currentDevice; currentDevice = currentDevice->next)
    {
        cout << ++i << ". " << currentDevice->name;
        if (currentDevice->description)
            cout << "(" << currentDevice->description << ")" << endl;
        else
            cout << "(�޿�������)\n";
    }
    if (i == 0)
    {
        cout << "\n δ�ҵ��ӿڣ���ȷ��WinPcap�Ѱ�װ��\n";
        return 0;
    }
    currentDevice = allDevices;
    int j;
    cout << "��ѡ��Ŀ���豸��";
    cin >> j;

    for (i = 0; i < j - 1; i++) {
        currentDevice = currentDevice->next;
    }
    //�򿪵�ǰ����ӿ�
    targetDevice = pcap_open(currentDevice->name, 100, PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL, errbuf);
    if (targetDevice == NULL) {
        cout << "���豸����: " << errbuf << endl;
        pcap_freealldevs(allDevices);
        return 0;
    }
    _beginthread(captureIP, 0, NULL);
    cin.ignore();
    getchar();
    pcap_freealldevs(allDevices);
    
}
