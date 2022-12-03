#include"myrouter.h"
using namespace std;
int main() {
	//获取本机ip
	getLocalIP();
	for (int i = 0; i < 2; i++)
	{
		printf("%s\t", ip[i]);
		printf("%s\n", mask[i]);
	}
	getLocalMac(inet_addr(ip[0]));
	print_mac(my_mac);

	RouteTable router_table;
	hThread = CreateThread(NULL, NULL, recv, LPVOID(&router_table), 0, &dwThreadId);

	int j;
	while (1)
	{
		//printf("\n\n请选择您要进行的操作：\n1. 添加路由表项\n2. 删除路由表项\n3. 打印路由表\n");
		printf("\n\n ************************************MENU*************************************\n");
		printf("[1] INSERT route entry\n");
		printf("[2] REMOVE route entry\n");
		printf("[3] PRINT  route table\n");
		scanf("%d", &j);
		route_entry *a=new route_entry;
		switch (j) {
		case 1:
			char m[50], n[50], h[50];
			printf("Please Enter: \n");
			printf("Net Mask：");
			scanf("%s", &m);
			a->netmask = inet_addr(m);
			printf("Destination Net：");
			scanf("%s", &n);
			a->dstNet = inet_addr(n);
			printf("Next Hop：");
			scanf("%s", &h);
			a->nextHop = inet_addr(h);
			a->type = true;
			router_table.insert(a);
			break;
		case 2:
			printf("Please Enter the index of removing route entry:  \n");
			router_table.printTable();
			int i;
			scanf("%d", &i);

			router_table.remove(i-1);
			break;
		case 3:
			router_table.printTable();
			break;
		default:
			printf("Error! Please ReEnter!\n");
			break;
		}
	}
	return 0;

}