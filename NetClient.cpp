//
// Created by AAGZ0452 on 2022/8/11.
//

#include "NetClient.h"
#include <iostream>
using namespace std;
void NetClient::init_client() {
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr(server_ip);
    server_addr.sin_port = htons(server_port);

    connect_fd = socket(AF_INET,SOCK_STREAM,0);
    if(connect_fd<0){
        cout<<"socket_error"<<endl;
    }

    int res = connect(connect_fd, (struct sockaddr*)(&server_addr), sizeof(server_addr));
    if (res == -1)
    {
        cout<<"connect error"<<endl;
    }
    cout<<"connect_fd:"<<connect_fd<<endl;
    cout<<"Connect to server success"<<endl;
}

int NetClient::one_time_receive(){
    //清空buffer
    cout<<"connect_fd:"<<connect_fd<<endl;
    memset(&buffer, 0, sizeof(buffer));
    if(connect_fd < 0) {
        cout<<"wrong connect_fd:"<<connect_fd<<endl;
        return -1;
    }
    uint32_t recv_bytes = recv(connect_fd, (char*)&buffer, sizeof(buffer), 0);
    cout<<"received size:"<<recv_bytes<<endl;
    cout<<"received buffer:"<<buffer<<endl;
    return recv_bytes;
}

bool NetClient::one_time_send(char * buf, uint32_t size){
    //连续发送  直到发送完
    cout<<"connect_fd:"<<connect_fd<<endl;
    while (size>0)
    {
        int SendSize= send(connect_fd, buf, size, 0);
        if(SendSize<0) {
            cout<<"send error"<<SendSize<<endl;
            return false;
        }
        size = size - SendSize;//用于循环发送且退出功能
        buf += SendSize;//用于计算已发buf的偏移量
    }
    cout<<"finish sending:"<<buf<<endl;
    return true;
}
