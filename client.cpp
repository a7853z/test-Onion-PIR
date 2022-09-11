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
#include "pir_client.h"
#include "NetClient.h"
#include "common.h"
#include "config_file.h"
#include <cassert>
#include <sstream>
#include <pthread.h>
#include <mutex>

using namespace std;
using namespace std::chrono;
using namespace seal;
using namespace seal::util;

typedef vector<Ciphertext> GSWCiphertext;
set<uint32_t> batch_query_index;
set<uint64_t> batch_id_set;
uint64_t * batch_query_ids = new uint64_t[10000];
mutex batch_result_mutex;

void process_ids(uint32_t number_of_groups){

    string one_line;
    //一个数组，记录每个文件的index
    uint32_t * index = new uint32_t [number_of_groups];
    for (int i = 0; i < number_of_groups; ++i) {
        index[i]=0;
    }

    ifstream query_data(id_file.c_str(), ifstream::in);

    ofstream write_map[number_of_groups];
    for (int i = 0; i < number_of_groups; ++i) {
        char path[40];
        sprintf(path, "id_map/id_map_%d.data", i);
        write_map[i].open(path, ofstream::out);
    }


    getline(query_data, one_line); //跳过首行‘id’
    while (getline(query_data, one_line)) {
        string one_id = one_line.substr(0, 18);
        uint32_t one_id_mod = get_id_mod(one_id, number_of_groups);
        write_map[one_id_mod]<<one_id<<" "<<index[one_id_mod]<<endl;
        index[one_id_mod]++;
    }

    for (int i = 0; i < number_of_groups; ++i) {
        write_map[i].close();
    }
    ofstream count_id;
    count_id.open("id_map/count_id.data");
    for (int i = 0; i < number_of_groups; ++i) {
        count_id<< i << " " << index[i]<<endl;
    }
    cout<<"Finishing process ids"<<endl;
}

//返回query_id在文件中的index，并给number_of_items赋值
uint32_t find_index(string query_id, uint32_t number_of_groups, uint32_t &number_of_items){
    uint32_t id_mod = get_id_mod(query_id, number_of_groups);
    cout << "id_mod:" << id_mod << endl;

    char path1[40];
    sprintf(path1, "id_map/id_map_%d.data", id_mod);
    ifstream read_map;
    read_map.open(path1, ifstream::in);
    string id; uint32_t index1;
    uint32_t index = -1;
    while(read_map>>id>>index1){
        if(id == query_id){
            index = index1;
            break;
        }
    }
    read_map.close();

    ifstream read_count;
    uint32_t mod, mod_count=0;
    read_count.open("id_map/count_id.data", ifstream::in);
    while(read_count>>mod>>mod_count){
        if(id_mod == mod) break;
    }
    number_of_items = mod_count;
    read_count.close();

    cout<<"query_id index:"<<index<<endl;
    return index;
}

void one_time_query(pir_client &client, NetClient &net_client, string query_id){
    //待修改
    //输入待查询id
    uint32_t number_of_items=0;
    // the query index to be queried, and assign value to number of items
    uint32_t ele_index = find_index(query_id, number_of_groups, number_of_items);

    while(ele_index==-1) {
        cout<<"query_id not found, enter again:"<<endl;
        cin>>query_id;
        ele_index = find_index(query_id, number_of_groups, number_of_items);
    }

    //根据query_index所在group 更新pir_params
    PirParams pir_params;
    gen_params(number_of_items,  size_per_item, N, logt,
               pir_params);
    client.updata_pir_params(pir_params);


    //获取query_id的sha256后的mod_id, 并发送给server
    uint32_t mod_id = get_id_mod(query_id, number_of_groups);
    cout<<"Client:: sending query id's mod_id to server"<<endl;
    net_client.one_time_send((char *)&mod_id, sizeof(mod_id));

    // index = int(ele_idx / ele_per_ptxt), ele_per_ptxt = int(N/ coffs_per_element) = 4096/4 = 1024
    // coffs_per_element=ceil(8 * 23 / (double) 60) = 4;
    uint64_t index = client.get_fv_index(ele_index, size_per_item);   // index of FV plaintext
    uint64_t offset = client.get_fv_offset(ele_index, size_per_item);  //offset in a plaintext

    cout << "Client: element index in the chosen Group = " << ele_index << " from [0, "
         << number_of_items -1 << "]" << endl;
    cout << "Client: FV index = " << index << ", FV offset = " << offset << endl;

    auto time_query_s = high_resolution_clock::now();
    PirQuery query = client.generate_query_combined(index);
    /*
    cout<<"Client:: query size = "<< query.size()<< endl;
    for (int i = 0; i < query.size(); ++i) {
        cout<<"query["<<i<<"] size:"<<query[i].size()<<endl;
    }*/
    cout<<"Client:: sending pir query to server"<<endl;
    //传query给server，传两个密文
    int query_size=0;
    for (int i = 0; i < 2; ++i) {
        stringstream ct_stream;
        Ciphertext ct = query[i][0];
        uint32_t ct_size = ct.save(ct_stream);
        query_size += ct_size;
        string ct_string = ct_stream.str();
        const char * ct_temp = ct_string.c_str();
        net_client.one_time_send(ct_temp, ct_size);
        //清空
        ct_string.clear();
        ct_stream.clear();
        ct_stream.str("");
    }
    auto time_query_e = high_resolution_clock::now();
    auto time_query_us = duration_cast<microseconds>(time_query_e - time_query_s).count();
    cout<<fixed<<setprecision(3)<<"Client: query generated, total bytes:"
        <<query_size/1024.0<<"KB"<<endl;
    cout << "Client: PIRClient query generation time: " << time_query_us / 1000 << " ms" << endl;

    //从server获取reply
    auto time_reply_s = high_resolution_clock::now();
    PirReply reply;
    Ciphertext ct;
    stringstream ct_stream;
    string ct_string;
    net_client.one_time_receive(ct_string);
    ct_stream<<ct_string;
    ct.load(client.newcontext_, ct_stream);
    ct_stream.clear();
    ct_stream.str("");
    ct_string.clear();
    reply.push_back(ct);
    cout<<"Client:: Receiving pir reply from server"<<endl;
    auto time_reply_e = high_resolution_clock::now();
    auto time_reply_us = duration_cast<microseconds>(time_reply_e - time_reply_s).count();
    cout << "Client: Server reply time: " << time_reply_us / 1000 << " ms" << endl;

    Plaintext rep= client.decrypt_result(reply);

    // Convert from FV plaintext (polynomial) to database element at the client
    vector<uint8_t> elems(N * logt / 8);
    coeffs_to_bytes(logt, rep, elems.data(), (N * logt) / 8);

    char pt[size_per_item];
    for (uint32_t i = 0; i < size_per_item; ++i) {
        pt[i] = elems[(offset * size_per_item) + i];
    }
    cout<<"query_id:"<<query_id<<" Retrived data:"<<pt<<endl;
    //cout << "Main: Reply num ciphertexts: " << reply.size() << endl;
}

void handle_one_batch_query(pir_client * client, uint32_t query_index) {
    uint32_t position = 0;
    set<uint32_t>::iterator iter;
    for (iter = batch_query_index.begin(); iter != batch_query_index.end() ; iter++) {
        if(*iter == query_index) break;
        position++;
    }

    NetClient net_client(ip, port);
    net_client.init_client();

    uint64_t index = query_index;
    cout << "Client:: Query index" << index << endl;

    auto time_query_s = high_resolution_clock::now();
    PirQuery query = client->generate_query_combined(index);
    cout<<"Client:: query size = "<< query.size()<< endl;
    for (int i = 0; i < query.size(); ++i) {
        cout<<"query["<<i<<"] size:"<<query[i].size()<<endl;
    }
    cout<<"Client:: sending one batch pir query to server"<<endl;
    //传query给server，传两个密文
    int query_size=0;
    for (int i = 0; i < 2; ++i) {
        stringstream ct_stream;
        Ciphertext ct = query[i][0];
        uint32_t ct_size = ct.save(ct_stream);
        query_size += ct_size;
        string ct_string = ct_stream.str();
        const char * ct_temp = ct_string.c_str();
        net_client.one_time_send(ct_temp, ct_size);
        //清空
        ct_string.clear();
        ct_stream.clear();
        ct_stream.str("");
    }
    auto time_query_e = high_resolution_clock::now();
    auto time_query_us = duration_cast<microseconds>(time_query_e - time_query_s).count();
    cout<<fixed<<setprecision(3)<<"Client: query generated, total bytes:"
        <<query_size/1024.0<<"KB"<<endl;
    cout << "Client: PIRClient query generation time: " << time_query_us / 1000 << " ms" << endl;

    //从server获取reply
    auto time_reply_s = high_resolution_clock::now();
    PirReply reply;
    Ciphertext ct;
    stringstream ct_stream;
    string ct_string;
    net_client.one_time_receive(ct_string);
    ct_stream<<ct_string;
    ct.load(client->newcontext_, ct_stream);
    ct_stream.clear();
    ct_stream.str("");
    ct_string.clear();
    reply.push_back(ct);
    cout<<"Client:: Receiving pir reply from server"<<endl;
    auto time_reply_e = high_resolution_clock::now();
    auto time_reply_us = duration_cast<microseconds>(time_reply_e - time_reply_s).count();
    cout << "Client:: Server reply time: " << time_reply_us / 1000 << " ms" << endl;

    Plaintext rep= client->decrypt_result(reply);

    // Convert from FV plaintext (polynomial) to database element at the client
    vector<uint8_t> elems(N * logt / 8);
    coeffs_to_bytes(logt, rep, elems.data(), (N * logt) / 8);

    uint32_t ele_per_ptxt = elements_per_ptxt(logt, N, size_per_item);
    uint32_t query_number = ceil(10000/(double)ele_per_ptxt);


    //lock_guard<mutex> lock(batch_result_mutex);
    uint64_t batch_id;
    ofstream write_batch_result;
    char path[40];
    sprintf(path, "batch_query_result.data");
    write_batch_result.open(path, ios::out|ios::app);
    char pt[size_per_item];
    for (int i = 0; i < ele_per_ptxt; ++i) {
        //char * pt;
        if((position == query_number-1) and i==10000%ele_per_ptxt) break; // last batch_query index
        batch_id = batch_query_ids[position*ele_per_ptxt+i];
        for (int j = 0; j < size_per_item; ++j) {
            pt[j]=elems[(i * size_per_item) + j];
        }
        //cout<<batch_id<<" "<<pt<<endl;
        write_batch_result<<batch_id<<" "<<pt<< endl;
    }
    write_batch_result.close();
    close(net_client.connect_fd);
}


void process_batch_ids(uint64_t *& batch_id_array){
    string one_line;
    auto count = 0;

    ifstream query_id(batch_id_file.c_str(), ifstream::in);
    getline(query_id, one_line); //跳过首行‘id’
    stringstream id_stream;
    while(getline(query_id, one_line)) {
        string one_id = one_line.substr(0, 18);
        id_stream<<one_id;
        uint64_t id;
        id_stream>>id;
        id_stream.clear();
        batch_id_set.insert(id);
        batch_id_array[count] = id;
        ++count;
    }
    query_id.close();
    cout<<"client::read "<<batch_id_set.size()<< " ids"<<endl;

    cout<<"client::Finishing reading batch_ids:"<<count<<endl;
}

uint64_t * random_pick() {
    set<uint64_t> random_id_set; //存储109万random_id
    uint32_t random_id_size = batch_id_number-10000;
    uint64_t * random_id_array = new uint64_t[random_id_size];
    random_device rd;

    uint64_t **group_ids;
    group_ids = new uint64_t *[number_of_groups];

    uint32_t * id_count = new uint32_t [number_of_groups];  //存储id_count数据
    cout<<"client::read all groups id_count"<<endl;
    ifstream read_count;
    read_count.open("id_map/count_id.data", ifstream::in);
    for (int i = 0; i < number_of_groups; ++i) {
        uint32_t mod, mod_count;
        read_count>>mod>>mod_count;
        id_count[i] = mod_count;
    }
    read_count.close();

    cout<<"client::read all ids"<<endl;
    ifstream read_map[number_of_groups];
    for (int i = 0; i < number_of_groups; ++i) {
        char path[40];
        sprintf(path, "id_map/id_map_%d.data", i);
        read_map[i].open(path, ifstream::in);
        uint32_t count = id_count[i];
        group_ids[i]= new uint64_t[count];
        uint64_t id, index;
        uint64_t iid;
        for (int j = 0; j < count; ++j) {
            read_map[i]>>id>>index;
            group_ids[i][j] = id;
        }
        read_map[i].close();
    }

    uint32_t random_group;
    uint32_t random_index ;
    for (int i = 0; i < random_id_size; ++i) {
        uint64_t random_number;

        //若已在两个set里面存在，重新选取
        while (true) {
            random_group = rd() % number_of_groups;
            random_index = rd() % id_count[random_group];
            random_number = group_ids[random_group][random_index];
            if(batch_id_set.count(random_number)==0 and random_id_set.count(random_number)==0) break;
        }
        random_id_set.insert(group_ids[random_group][random_index]);
        random_id_array[i]=group_ids[random_group][random_index];
    }

    cout<<"client::random id size:"<< random_id_set.size()<<endl;

    for(int i=0; i<number_of_groups; ++i)
        delete [] group_ids[i];
    delete [] group_ids;
    return random_id_array;
}

void batch_id_index_process() {
    process_batch_ids(batch_query_ids);
    uint64_t * random_pick_ids = random_pick();
    auto ele_per_ptxt = elements_per_ptxt(logt, N, size_per_item);  //1024 = 4096/4
    uint32_t query_number = ceil(10000/(double)ele_per_ptxt);
    uint32_t ptxt_number = ceil(batch_id_number/(double)ele_per_ptxt);
    ofstream write_batch_query;
    char path[40];
    sprintf(path, "batch_query_proprocess.data");
    write_batch_query.open(path, ofstream::out);

    //生成随机query_index
    random_device rd;
    for (int i = 0; i < query_number; ++i) {
        uint32_t query_index = rd() % ptxt_number;
        batch_query_index.insert(query_index);
        write_batch_query<<query_index<< endl;
    }

    //写100w  id-index 到文件
    uint32_t current_pt_index;
    uint32_t batch_id_idx = 0;
    uint32_t random_id_idx = 0;
    for (int i = 0; i < batch_id_number; ++i) {
        current_pt_index = i/ele_per_ptxt;
        //取batch_id
        if(batch_query_index.count(current_pt_index)!=0 and batch_id_idx<10000) {
            write_batch_query<<batch_query_ids[batch_id_idx]<<" "<<i<< endl;
            ++batch_id_idx;
        } else {
            write_batch_query<<random_pick_ids[random_id_idx]<<" "<<i<< endl;
            ++random_id_idx;
        }
    }

    delete [] random_pick_ids;
}

//
void get_batch_query_buffer(char * & buffer) {
    auto ele_per_ptxt = elements_per_ptxt(logt, N, size_per_item);  //1024 = 4096/4
    uint32_t query_number = ceil(10000/(double)ele_per_ptxt);
    uint32_t ptxt_number = ceil(batch_id_number/(double)ele_per_ptxt);
    set<uint32_t> query_index;
    ifstream query_data("batch_query_proprocess.data", ifstream::in);

    batch_query_index.clear();
    uint32_t index;
    for (int i = 0; i < query_number; ++i) {
        query_data>>index;
        batch_query_index.insert(index);
    }
    //send 1million 8bytes-id to server in order.
    uint64_t id;
    uint32_t offset=0;
    for (int i = 0; i < batch_id_number; ++i) {
        query_data >> id >> index;
        memcpy(buffer+offset, (char*)&id ,sizeof(id));
        offset += sizeof(id);
    }
    query_data.close();
}

void send_public_params (pir_client &client, NetClient &net_client){
    //生成Galois keys，并传给Server
    GaloisKeys galois_keys = client.generate_galois_keys();
    cout << "Client: Setting Galois keys...";
    stringstream galois_stream;
    int galois_size = galois_keys.save(galois_stream);
    string g_string = galois_stream.str();
    const char * galois_temp = g_string.c_str();

    cout<<fixed<<setprecision(3)<<"Client:: Sending galois_keys to server, key size:"
        <<galois_size/1024.0<<"KB"<<endl;

    net_client.one_time_send(galois_temp, galois_size);
    //清空stream和string
    g_string.clear();
    galois_stream.clear();
    galois_stream.str("");

    //生成sk的密文，并传给server
    GSWCiphertext enc_sk=client.get_enc_sk();

    int enc_sk_size = 0;
    cout<<"Client::sending enc_sk to server"<<endl;
    for (int i = 0; i < enc_sk.size(); ++i) {
        //测试数据vector总是14密文，所以直接发密文，如果有多个密文需要先发vector size
        stringstream ct_stream;
        Ciphertext ct = enc_sk[i];
        uint32_t ct_size = ct.save(ct_stream);
        enc_sk_size += ct_size;
        string ct_string = ct_stream.str();
        const char * ct_temp = ct_string.c_str();
        net_client.one_time_send(ct_temp, ct_size);
        //清空
        ct_string.clear();
        ct_stream.clear();
        ct_stream.str("");
    }
    cout<<fixed<<setprecision(3)<<"Client:: enc_sk size:"<<enc_sk_size/1024.0<<"KB"<<endl;
}

int handle_batch_query() {
    cout<<"Client::Begin Batch Query Offline Preprocessing: picking 110w random ids include batch query ids" <<endl;
    auto time_offline_s = high_resolution_clock::now();

    if(batch_id_preprocess) {
        batch_id_index_process();
    } else {
        process_batch_ids(batch_query_ids);
    }

    char * buffer = new char[batch_id_number * 8];
    get_batch_query_buffer(buffer);

    uint64_t data;
    memcpy(&data, buffer, sizeof(data));
    cout<<"one sampel batch id"<<data<<endl;

    uint32_t buffer_size = batch_id_number*8; //1million uint64_t
    auto time_offline_e = high_resolution_clock::now();
    auto time_offline_us = duration_cast<microseconds>(time_offline_e - time_offline_s).count();
    cout << "Client::Batch query offline preprocess time: " << time_offline_us / 1000 << " ms" << endl;

    cout<<"Client::Begin online batch query"<<endl;
    //send public param first
    auto time_online_s = high_resolution_clock::now();
    NetClient net_client(ip, port);
    net_client.init_client();
    // 初始化加密参数和PIR参数
    PirParams pir_params;
    EncryptionParameters parms(scheme_type::BFV);
    set_bfv_parms(parms);   //N和logt在这里设置
    gen_params(batch_id_number,  size_per_item, N, logt,
               pir_params);
    // Initialize PIR client....
    pir_client client(parms, pir_params);
    send_public_params(client, net_client);


    net_client.one_time_send(buffer, buffer_size);
    close(net_client.connect_fd);
    delete buffer;
    buffer = nullptr;
    set<uint32_t>::iterator iter;
    uint32_t query_index;
    for (iter = batch_query_index.begin(); iter != batch_query_index.end(); iter++) {
        query_index = *iter;
        thread t(handle_one_batch_query, &client, query_index);
        t.join();
    }
    auto time_online_e = high_resolution_clock::now();
    auto time_online_us = duration_cast<microseconds>(time_online_e - time_online_s).count();
    cout<<"Client::Batch query online preprocess time: " << time_online_us / 1000 << " ms" << endl;
    cout<<"Client::Finish batch query, result has been written to batch_query_result.data"<<endl;
    return 1;
}


int main(int argc, char* argv[]){
    ensure_dir("id_map");
    if (!path_exists(id_file.c_str())) {
        cerr << id_file << " not exists!" << endl;
        return -1;
    }
    if (!path_exists(batch_id_file.c_str())) {
        cerr << batch_id_file << " not exists!" << endl;
        return -1;
    }

    ConfigFile::set_path("client.conf");
    ConfigFile config = ConfigFile::get_instance();
    if(config.key_exist("N")) N = config.get_value_uint32("N");
    if(config.key_exist("logt")) logt = config.get_value_uint32("logt");
    if(config.key_exist("size_per_item")) size_per_item = config.get_value_uint64("size_per_item");
    if(config.key_exist("number_of_groups")) number_of_groups = config.get_value_uint32("number_of_groups");
    if(config.key_exist("id_file")) id_file = config.get_value("id_file");
    if(config.key_exist("process_id")) process_id = config.get_value_bool("process_id");
    if(config.key_exist("batch_id_file")) batch_id_file = config.get_value("batch_id_file");

    //从conf文件获取 ip和port, 否则默认值127.0.0.1：11111
    if(config.key_exist("ip")) ip = config.get_value("ip");
    if(config.key_exist("port")) port = config.get_value_int("port");
    if(config.key_exist("batch_id_preprocess")) batch_id_preprocess = config.get_value_bool("batch_id_preprocess");


    if (argc>1 and string(argv[1])=="batch") {
        return handle_batch_query();
    }

    NetClient net_client(ip, port);
    net_client.init_client();

    uint32_t number_of_items = 0;  //百万不可区分度， 具体需要从服务器获取

    //pre-process ids
    if(process_id) {
        process_ids(number_of_groups);
    }

    // 初始化加密参数和PIR参数
    PirParams pir_params;
    EncryptionParameters parms(scheme_type::BFV);
    set_bfv_parms(parms);   //N和logt在这里设置
    gen_params(number_of_items,  size_per_item, N, logt,
               pir_params);

    // Initialize PIR client....
    pir_client client(parms, pir_params);

    send_public_params(client, net_client);

    while(true){
        string query_id;
        cout<<"Client:: Input a query id:"<<endl;
        cin>> query_id;
        one_time_query(client, net_client, query_id);
    }
    return 0;
}

