#include <windows.h>
#include<iostream>
#include<stdio.h>
using namespace std;
const int n = 600000;
int* a = new int[n];
void loop1(int n, int *a) {
    for (int i = 0; i < n; i++) {
        a[i] = a[i] * 2000;
        a[i] = a[i] / 10000;
    }
}
void loop2(int n, int* a) {
    int* b = a;
    for (int i = 0; i < n; i++) {
        *b = *b * 2000;
        *b = *b / 10000;
        b++;
    }
}
int main() {
    for (int i = 0; i < n; i++) {
        a[i] = rand() % 100;
    }
    long long head, tail, freq;
    QueryPerformanceFrequency((LARGE_INTEGER*)&freq);
    QueryPerformanceCounter((LARGE_INTEGER*)&head);
    int count = 10000;
    for(int i=0;i< count;i++)
        loop1(n, a);
    
    QueryPerformanceCounter((LARGE_INTEGER*)&tail);
    cout << "loop1:" << ((tail - head) * 1000.0 / freq)/ count << "ms" << endl;

    for (int i = 0; i < n; i++) {
        a[i] = rand() % 100;
    }
    QueryPerformanceFrequency((LARGE_INTEGER*)&freq);
    QueryPerformanceCounter((LARGE_INTEGER*)&head);
    for (int i = 0; i < count; i++)
        loop2(n, a);
    QueryPerformanceCounter((LARGE_INTEGER*)&tail);
    cout << "loop2:" << ((tail - head) * 1000.0 / freq) / count << "ms" << endl;
}