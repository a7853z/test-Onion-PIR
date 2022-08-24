//
// Created by AAGZ0452 on 2022/8/11.
//
#include "NetServer.h"
using namespace std;

int NetServer::init_net_server() {
    //初始化
    cout<<"server ip:"<<server_ip<<" server port:"<<server_port<<endl;
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

    ret = listen(listen_fd, 128);
    if(ret == -1) {
        cout<<"SERVER: listen error"<<endl;
        return -1;
    }
    cout<<"SERVER: listen success, listen fd:"<<listen_fd<<endl;
    uint32_t client_addr_len = sizeof(client_addr);
    char client_ip[20];
    cout<<"listen_fd:"<<listen_fd<<endl;

    connect_fd = accept(listen_fd, (sockaddr*)(&client_addr), &client_addr_len);
    if(connect_fd<0){
        cout<<"accept error"<<endl;
    }

    cout<<"connect_fd:"<<connect_fd<<endl;
    //输出客户端信息
    cout << "client ip:" << inet_ntoa(client_addr.sin_addr)
         << "client port:" <<  ntohs(client_addr.sin_port)
         << "connect_fd:"<< connect_fd <<endl;
    return connect_fd;
}

int NetServer::one_time_receive(string &message){
    //清空buffer
    memset(&buffer, 0, sizeof(buffer));
    if(connect_fd < 0) {
        cout<<"wrong connect_fd:"<<connect_fd<<endl;
        return -1;
    }
    //receive length first
    uint32_t recv_bytes;
    uint32_t size;
    recv_bytes = recv(connect_fd, buffer, sizeof(buffer), 0);
    memcpy(&size, buffer, sizeof(size));
    cout<<"received bytes:"<<recv_bytes<<" packet length:"<<size<<endl;

    size-=(recv_bytes-sizeof(size));

    //when recv_butes==BUFFER_SIZE extra char
    string temp(buffer+4, recv_bytes-sizeof(size));
    cout<<(buffer[5]-'\0')<<endl;
    message+=temp;
    cout<<"message length:"<<message.length()<<endl;
    //buffer[recv_bytes]='\0';


    while(size>0){
        memset(&buffer, 0, sizeof(buffer));
        recv_bytes = recv(connect_fd, buffer, sizeof(buffer), 0);
        //buffer[recv_bytes]='\0';
        cout<<"received bytes:"<<recv_bytes<<endl;

        //when recv_bytes==BUFFER_SIZE 导致 extra char
        string temp1(buffer, recv_bytes);
        message += temp1;
        cout<<"message length:"<<message.length()<<endl;
        size-=recv_bytes;
    }
    cout<<"size"<<size<<endl;
    //send 'finished'
    cout<<"received, sending finished message"<<endl;
    char *msg = "finished";
    send(connect_fd, msg, strlen(msg), 0);
    return size;
}

bool NetServer::one_time_send(const char * buf, uint32_t size){
    //连续发送  直到发送完
    cout<<"send ready:"<<send_ready<<endl;
    if(!send_ready) cout<<"not ready to send, wait till finish"<<endl;
    while(!send_ready) {
    }

    //send length first
    uint32_t length = size;
    cout<<"sending message length:"<<length<<endl;
    send(connect_fd, (char *)&length, sizeof(length), 0);

    uint32_t sended = 0;
    while (size>0)
    {
        int SendSize= send(connect_fd, buf+sended, size, 0);
        sended +=SendSize;
        cout<<"Sended size:"<<SendSize<<endl;
        if(SendSize<0) {
            cout<<"send error"<<SendSize<<endl;
            return false;
        }
        size = size - SendSize;//用于循环发送且退出功能
        //buf += SendSize;//用于计算已发buf的偏移量
    }
    cout<<"finish sending"<<endl;
    send_ready = false;

    cout<<"waiting for finish reply"<<endl;
    memset(&buffer, 0, sizeof(buffer));
    if(connect_fd < 0) {
        cout<<"wrong connect_fd:"<<connect_fd<<endl;
        return -1;
    }
    uint32_t recv_bytes = recv(connect_fd, (char*)&buffer, 8, 0);  //"finished" length 8
    //buffer[recv_bytes] = '\0';

    if(strcmp(buffer, "finished")==0) {
        cout<<"finished sending a message"<<endl;
        send_ready = true;
    }
    else {
        cout<<"didn't receive the finish message, received buffer:"<<buffer<<endl;
    }
    return true;
}



