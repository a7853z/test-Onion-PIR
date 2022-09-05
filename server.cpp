//
// Created by AAGZ0452 on 2022/8/4.
//
#include "seal/util/polyarithsmallmod.h"
#include "seal/util/polycore.h"
#include <chrono>
#include <iostream>
#include <fstream>
#include <algorithm>
#include <random>
#include <pthread.h>
#include "nfl.hpp"
#include "tools.h"
#include "seal/seal.h"
#include "external_prod.h"
#include "util.h"
#include "pir.h"
#include "pir_server.h"
#include "NetServer.h"
#include "common.h"
#include "config_file.h"
#include <cassert>
#include <sstream>

using namespace std;
using namespace std::chrono;
using namespace seal;
using namespace seal::util;

void process_datas(uint32_t number_of_groups){

    string id_file = ConfigFile::get_instance().get_value("data_file");

    //一个数组，记录每个文件的index
    uint32_t * index = new uint32_t [number_of_groups];
    for (int i = 0; i < number_of_groups; ++i) {
        index[i]=0;
    }

    ifstream query_data(id_file.c_str(), ifstream::in);

    ofstream write_map[number_of_groups];
    for (int i = 0; i < number_of_groups; ++i) {
        char path[40];
        sprintf(path, "data_map/data_map_%d.data", i);
        write_map[i].open(path, ofstream::out|ofstream::app);
    }

    string one_line;
    getline(query_data, one_line); //跳过首行‘id’
    while (getline(query_data, one_line)) {
        string one_id = one_line.substr(0, 18);
        string output = one_line.substr(19, one_line.length());
        //如果不足23位  补齐0
        int pad_length = 23-output.length();
        if (pad_length>0){
            string pad_str(pad_length,'0');
            output = output+pad_str;
        }

        uint32_t one_id_mod = get_id_mod(one_id, number_of_groups);
        // id index data
        write_map[one_id_mod]<<one_id<<" "<<index[one_id_mod] << " " << output <<endl;
        index[one_id_mod]++;
    }

    for (int i = 0; i < number_of_groups; ++i) {
        write_map[i].close();
    }

    //count of each data file
    ofstream count_data;
    count_data.open("data_map/count_data.data");
    for (int i = 0; i < number_of_groups; ++i) {
        count_data<< i << " " << index[i]<<endl;
    }
}

unique_ptr<uint8_t[]> load_data(uint32_t id_mod, uint32_t item_size, uint32_t & item_number){
    cout << "Server: load data for id_mod:" << id_mod << endl;

    // read count of mod_id's data file
    ifstream read_count;
    string mod, mod_count;
    uint32_t count;
    read_count.open("data_map/count_data.data", ifstream::in);
    while(read_count>>mod>>mod_count){
        if(id_mod == atoi(mod.c_str())){
            count = atoi(mod_count.c_str());
            break;
        }
    }
    item_number = count;
    read_count.close();

    //read data to db
    char path1[40];
    sprintf(path1, "data_map/data_map_%d.data", id_mod);
    cout<<"Server:: load data from:"<<path1<<endl;
    ifstream read_map;
    read_map.open(path1, ifstream::in);
    auto db(make_unique<uint8_t[]>(count * item_size));

    string id, index, data;
    for (int i = 0; i < count; ++i) {
        read_map>>id>>index>>data;
        for (int j = 0; j < item_size; ++j) {
            db.get()[i*item_size+j]=data[j];
        }
    }
    return db;
}

void process_split_dbs(pir_server & server, uint32_t number_of_groups) {
    for (int i = 0; i < number_of_groups; ++i) {
        uint32_t id_mod = i;
        uint32_t number_of_items = 0;
        auto db = load_data(id_mod, size_per_item, number_of_items);
        PirParams pir_params;
        gen_params(number_of_items,  size_per_item, N, logt,
                   pir_params);
        server.updata_pir_params(pir_params);
        server.set_database(move(db), number_of_items, size_per_item);
        //plaintext decomposition
        server.preprocess_database();
        char split_db_file[40];
        sprintf(split_db_file, "split_db/split_db_%d.bin", id_mod);
        server.write_split_db2disk(split_db_file);
    }
}

void update_item_number(uint32_t id_mod, uint32_t & item_number) {
    ifstream read_count;
    string mod, mod_count;
    uint32_t count;
    read_count.open("data_map/count_data.data", ifstream::in);
    while(read_count>>mod>>mod_count){
        if(id_mod == atoi(mod.c_str())){
            count = atoi(mod_count.c_str());
            break;
        }
    }
    item_number = count;
}

bool handle_one_query(ConnData* conn_data, pir_server &server){
    // Recommended values: (logt, d) = (12, 2) or (8, 1).

    string g_string;
    uint32_t id_mod; //get from client
    int ret;
    ret = NetServer::one_time_receive(conn_data, g_string);
    if (ret == -1) return false;
    memcpy(&id_mod, g_string.c_str(), sizeof(id_mod));
    bool is_preproccessed = (conn_data->last_id_mod==id_mod);
    conn_data->last_id_mod = id_mod;
    cout<<"Server::getting id_mod from client:"<<id_mod<<endl;
    g_string.clear();


    //get query from client
    PirQuery query;
    //實際是query維度為2*1 後面擴展為先傳維度，再根據維度接收密文
    cout<<"Server:: receive pir_query from client:"<<endl;
    for (int i = 0; i < 2; ++i) {
        GSWCiphertext query_ct;
        Ciphertext ct;
        stringstream ct_stream;
        string ct_string;
        ret = NetServer::one_time_receive(conn_data, ct_string);
        if (ret == -1) return false;
        ct_stream<<ct_string;
        ct.load(server.newcontext_, ct_stream);
        ct_stream.clear();
        ct_stream.str("");
        ct_string.clear();
        query_ct.push_back(ct);
        query.push_back(query_ct);
    }

    auto time_pre_s = high_resolution_clock::now();
    //convert db data to a vector of plaintext: covert to coefficients of polynomials first
    if(!is_preproccessed) {
        //本地讀取待查詢數據庫
        update_item_number(id_mod, conn_data->number_of_items);
        PirParams pir_params;
        gen_params(conn_data->number_of_items,  size_per_item, N, logt,
                   pir_params);
        server.updata_pir_params(pir_params);
        server.read_split_db_from_cache(id_mod);
    }
    else {
        cout<<"Server:: db is preprocessed, skip!"<<endl;
    }

    auto time_pre_e = high_resolution_clock::now();
    auto time_pre_us = duration_cast<microseconds>(time_pre_e - time_pre_s).count();
    cout << "Server: PIRServer data base pre-processing time: " << time_pre_us / 1000 << " ms" << endl;

    auto time_server_s = high_resolution_clock::now();
    PirReply reply = server.generate_reply_combined(query, 0); // generate reply and remote it to client

    //發送reply  reply只含有一個密文
    cout<<"Server:: send pir result to client:"<<endl;
    Ciphertext ct = reply[0];
    stringstream ct_stream;
    uint32_t ct_size = ct.save(ct_stream);
    string ct_string = ct_stream.str();
    const char * ct_temp = ct_string.c_str();
    NetServer::one_time_send(conn_data, ct_temp, ct_size);
    //清空
    ct_string.clear();
    ct_stream.clear();
    ct_stream.str("");
    auto time_server_e = high_resolution_clock::now();
    auto time_server_us = duration_cast<microseconds>(time_server_e - time_server_s).count();
    cout<<fixed<<setprecision(3)<<"Server: PIR Reply size:"<<ct_size/1024.0<<"KB"<<endl;
    cout << "Server: PIRServer reply generation time: " << time_server_us / 1000 << " ms"
         << endl;
    
    return true;
}

// 创建一个线程，用来处理这个连接
void handle_connection(int connect_fd) {
    ConnData* conn_data = new ConnData();
    conn_data->connect_fd = connect_fd;

    PirParams pir_params;
    EncryptionParameters parms(scheme_type::BFV);
    set_bfv_parms(parms);   //N和logt在这里设置
    gen_params(0,  size_per_item, N, logt, pir_params);  //number_of_items 初始0
    //
    cout << "Server: Initializing server for a Client, Client connect_fd:"<<connect_fd << endl;
    pir_server server(parms, pir_params);

    string g_string;
    int ret;
    ret = NetServer::one_time_receive(conn_data, g_string);
    if (ret == -1) return;
    cout<<"received galois keys from client, key length(bytes):"<<g_string.length()<<endl;
    stringstream g_stream;
    g_stream<<g_string;

    GaloisKeys server_galois;
    server_galois.load(server.newcontext_, g_stream);
    cout << "Server: Setting Galois keys..."<<endl;
    server.set_galois_key(0, server_galois);
    //清空stream和string
    g_string.clear();
    g_stream.clear();
    g_stream.str("");

    //get enc_sk from the client
    GSWCiphertext enc_sk;
    //get from the client, for query unpacking get top l rows for GSW ciphertext
    cout<<"receive enc_sk from client:"<<endl;
    for (int i = 0; i < 14; ++i) {
        Ciphertext ct;
        stringstream ct_stream;
        string ct_string;
        NetServer::one_time_receive(conn_data, ct_string);
        ct_stream<<ct_string;
        ct.load(server.newcontext_, ct_stream);
        enc_sk.push_back(ct);
        ct_stream.clear();
        ct_stream.str("");
        ct_string.clear();
    }
    server.set_enc_sk(enc_sk);

    while(handle_one_query(conn_data, server)) {
    }
}

int main(int argc, char* argv[]){
    ConfigFile::set_path("server.conf");
    ConfigFile config = ConfigFile::get_instance();
    if(config.key_exist("N")) N = config.get_value_uint32("N");
    if(config.key_exist("logt")) logt = config.get_value_uint32("logt");
    if(config.key_exist("size_per_item")) size_per_item = config.get_value_uint64("size_per_item");
    if(config.key_exist("number_of_groups")) number_of_groups = config.get_value_uint32("number_of_groups");
    if(config.key_exist("process_split_db")) process_split_db = config.get_value_bool("process_split_db");

    //pre-process ids
    if(config.key_exist("process_data"))  process_data = config.get_value_bool("process_data");
    if(process_data) {
        process_datas(number_of_groups);
    }

    if(process_split_db) { // 为true时不要多线程
        //初始化参数，和server
        PirParams pir_params;
        EncryptionParameters parms(scheme_type::BFV);
        set_bfv_parms(parms);   //N和logt在这里设置
        gen_params(0,  size_per_item, N, logt, pir_params);  //number_of_items 初始0
        //
        cout << "Server: Initializing server." << endl;
        pir_server server(parms, pir_params);
        cout<<"Server:: Process all split_db"<<endl;
        process_split_dbs(server, number_of_groups);
    }

    //从conf文件获取 ip和port, 否则默认值127.0.0.1：11111
    if(config.key_exist("ip")) ip = config.get_value("ip");
    if(config.key_exist("port")) port = config.get_value_int("port");

    NetServer net_server(ip, port);
    net_server.init_net_server();
    while (true) {
        int connect_fd = net_server.wait_connection();
        thread t(handle_connection, connect_fd);
        t.detach();
    }

    return 0;
}

