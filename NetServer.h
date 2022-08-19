//
// Created by AAGZ0452 on 2022/8/11.
//

#ifndef ONIONPIR_NETSERVER_H
#define ONIONPIR_NETSERVER_H

#endif //ONIONPIR_NETSERVER_H

#include <errno.h>
#include <iostream>
#include <string>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <netdb.h>
#include <sys/uio.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <fstream>
using namespace std;

#define BUFFER_SIZE 400000

class NetServer {
public:
    int listen_fd = -1, connect_fd = -1;
    uint32_t server_port;
    const char* server_ip;
    sockaddr_in server_addr;
    sockaddr_in client_addr;
    uint32_t sin_size, data_len;
    char buffer[BUFFER_SIZE];  //40w字节buffer用来与client通讯
    int init_net_server();  //initialize net server and listen
    int one_time_receive(string &message);
    bool one_time_send(char * buf, uint32_t size);
    bool send_ready = true;
    NetServer(char* ip ="127.0.0.1" , int port = 11111) {
        server_ip = ip;
        server_port = port;
    }
    ~NetServer(){
        close(listen_fd);
        close(connect_fd);
    }
};

