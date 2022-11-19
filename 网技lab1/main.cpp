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
typedef struct FrameHeader_t {//以太网数据帧首部
    BYTE DesMAC[6];
    BYTE SrcMAC[6];
    WORD FrameType;
}FrameHeader_t;
typedef struct IPHeader_t {//定义IP首部
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
typedef struct Data_t {//包含帧首部和IP首部的数据包
    FrameHeader_t FrameHeader;
    IPHeader_t IPHeader;
}Data_t;
#pragma pack()
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
void WordToBitStr(WORD b) {
    cout << bitset<16>(b);
}
void captureIP(void* a) {
    struct pcap_pkthdr* pkt_header;
    const u_char* pkt_data;
    pkt_data = NULL;
    int i;
    int num = 1;
    for(i= pcap_next_ex(targetDevice, &pkt_header, &pkt_data);i>=0;){//进行数据包捕获
        if (i == 0)continue;
        else {
            Data_t* IPPacket;
            IPPacket = (Data_t*)pkt_data; //创建变量放入捕获到的网络数据包
            cout << "第" << num << "个数据包：" << endl;
            cout << "源MAC地址：  " << *(ByteToHexStr(IPPacket->FrameHeader.SrcMAC, 6)) << endl;
            cout << "目的MAC地址：" << *(ByteToHexStr(IPPacket->FrameHeader.DesMAC, 6)) << endl;
            cout << "源IP地址：   " << GetIp(IPPacket->IPHeader.SrcIP) << endl;
            cout << "目的IP地址： " << GetIp(IPPacket->IPHeader.DstIP) << endl;
            cout << "类型：       " << IPPacket->FrameHeader.FrameType << endl;
            cout << "长度：       " << IPPacket->IPHeader.TotalLen << endl;

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
    }
    if (i == 0)
    {
        cout << "\n 未找到接口；请确认WinPcap已安装！\n";
        return 0;
    }
    currentDevice = allDevices;
    int j;
    cout << "请选择目标设备：";
    cin >> j;

    for (i = 0; i < j - 1; i++) {
        currentDevice = currentDevice->next;
    }
    //打开当前网络接口
    targetDevice = pcap_open(currentDevice->name, 100, PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL, errbuf);
    if (targetDevice == NULL) {
        cout << "打开设备错误: " << errbuf << endl;
        pcap_freealldevs(allDevices);
        return 0;
    }
    _beginthread(captureIP, 0, NULL);
    cin.ignore();
    getchar();
    pcap_freealldevs(allDevices);
    
}
