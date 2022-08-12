//
// Created by AAGZ0452 on 2022/8/11.
//
#include "NetServer.h"
#include <iostream>
using namespace std;

int NetServer::init_net_server() {
    //初始化
    memset(&server_addr, 0, sizeof(server_addr));

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(server_port);
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);

    listen_fd = socket(AF_INET,SOCK_STREAM,0);
    int ret;
    ret = bind(listen_fd,(struct sockaddr*)&server_addr,sizeof(server_addr));
    if(ret == -1) {
        cout<<"SERVER: bind error"<<endl;
        return -1;
    }else {
        cout<<"SERVER: bind success"<<endl;
    }

    ret = listen(listen_fd,128);
    if(ret == -1) {
        cout<<"SERVER: listen error"<<endl;
        return -1;
    }
    cout<<"SERVER: listen success, listen fd:"<<listen_fd<<endl;
    return listen_fd;
}

int NetServer::connect_client() {
    uint32_t client_addr_len = sizeof(client_addr);
    char client_ip[20];
    cout<<"listen_fd:"<<listen_fd<<endl;
    connect_fd = accept(listen_fd, (sockaddr*)(&client_addr), &client_addr_len);
    if(connect_fd < 0){
        cout<<"accept error"<<endl;
        return -1;
    }
    cout<<"connect_fd:"<<connect_fd<<endl;
    //输出客户端信息
    cout << "client ip:" << inet_ntoa(client_addr.sin_addr)
         << "client port:" <<  ntohs(client_addr.sin_port)
         << "connect_fd:"<< connect_fd <<endl;
    return connect_fd;
}

int NetServer::one_time_receive() {
    //清空buffer
    cout<<"connect_fd:"<<connect_fd<<endl;
    memset(&buffer, 0, sizeof(buffer));

    int recv_bytes;
    while(1){
        recv_bytes = recv(connect_fd, buffer, sizeof(buffer), 0);
        if(recv_bytes>0){
            break;
        }
    }
    buffer[recv_bytes]='\0';
    cout<<"message received, buffer:"<<buffer<<endl;
    return recv_bytes;
}

bool NetServer::one_time_send(char * buf, uint32_t size) {
    cout<<"connect_fd:"<<connect_fd<<endl;
    //连续发送  直到发送完
    while (size>0)
    {
        int SendSize= send(connect_fd, buf, size, 0);
        if(SendSize<0){
            cout<<"send error"<<SendSize<<endl;
            return false;
        }
        size = size - SendSize;//用于循环发送且退出功能
        buf += SendSize;//用于计算已发buf的偏移量
    }
    cout<<"finish sending"<<endl;
    return true;
}


