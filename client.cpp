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
#include "SHA256.h"

using namespace std;
using namespace std::chrono;
using namespace seal;
using namespace seal::util;

typedef vector<Ciphertext> GSWCiphertext;

uint32_t get_id_mod(string query_id, uint32_t number_of_groups)
{
    SHA256 sha;
    sha.update(query_id);
    uint8_t * digest = sha.digest();
    uint32_t id_mod = SHA256::mod(digest, number_of_groups);
    //cout << SHA256::toString(digest) << " mod:"<<id_mod<<std::endl;
    delete[] digest;
    return id_mod;
}

void process_ids(uint32_t number_of_groups){

    string id_file = "../query_data.csv";
    string one_line;
    //一个数组，记录每个文件的index
    uint32_t * index = new uint32_t [90];
    for (int i = 0; i < 90; ++i) {
        index[i]=0;
    }

    ifstream query_data(id_file.c_str(), ifstream::in);

    ofstream write_map[90];
    for (int i = 0; i < 90; ++i) {
        char path[40];
        sprintf(path, "id_map_%d.data", i);
        write_map[i].open(path, ofstream::out|ofstream::app);
    }


    getline(query_data, one_line); //跳过首行‘id’
    for (int i = 0; i < 100000000; ++i) {
        getline(query_data, one_line);
        string one_id = one_line.substr(0, 18);
        uint32_t one_id_mod = get_id_mod(one_id, number_of_groups);
        write_map[one_id_mod]<<one_id<<" "<<index[one_id_mod]<<endl;
        index[one_id_mod]++;
    }

    for (int i = 0; i < 90; ++i) {
        write_map[i].close();
    }
}

uint32_t find_index(string query_id, uint32_t number_of_groups){
    uint32_t id_mod = get_id_mod(query_id, number_of_groups);
    cout << "id_mod:" << id_mod << endl;

    char path1[40];
    sprintf(path1, "id_map_%d.data", id_mod);
    ifstream read_map("id_map.data", ifstream::in);
    read_map.open(path1, ifstream::in);
    string id, index1;
    uint32_t index = -1;
    while(read_map>>id>>index1){
        if(id == query_id){
            index = atoi(index1.c_str());
            break;
        }
    }
    read_map.close();
    cout<<"query_id index:"<<index<<endl;
    return index;
}

int main(){

    uint64_t number_of_items = 1<<20;  //百万不可区分度， 具体需要从服务器获取
    uint64_t size_per_item = 23;       //每条记录需要的占用23字节
    uint32_t N = 4096;
    uint32_t number_of_groups = 90;

    //pre-process ids
    bool process_id = false;
    if(process_id) {
        process_ids();
    }


    // Recommended values: (logt, d) = (12, 2) or (8, 1).
    uint32_t logt = 60;
    PirParams pir_params;
    EncryptionParameters parms(scheme_type::BFV);
    set_bfv_parms(parms);   //N和logt在这里设置
    gen_params( number_of_items,  size_per_item, N, logt,
                pir_params);


    // Initialize PIR client....
    pir_client client(parms, pir_params);
    GaloisKeys galois_keys = client.generate_galois_keys();

    //Galois keys需要传给Server，待补充

    cout << "Main: Setting Galois keys...";

    //待修改
    //输入待查询id
    string query_id;
    cout<<"input a query id:"<<endl;
    cin>> query_id;
    cout<<"query id:"<<query_id<<endl;

    //获取query_id的sha256后的mod_id
    //存储SHA256取模相同的一组id

    // the query index to be queried
    uint32_t ele_index = find_index(query_id, number_of_groups);

    if(ele_index==-1){
        cout<<"query_id not existed!"<<endl;
        return 0;
    }


    uint64_t index = client.get_fv_index(ele_index, size_per_item);   // index of FV plaintext
    uint64_t offset = client.get_fv_offset(ele_index, size_per_item);

    cout << "Main: element index in the chosen Group = " << ele_index << " from [0, "
    << number_of_items -1 << "]" << endl;
    cout << "Main: FV index = " << index << ", FV offset = " << offset << endl;


    auto time_query_s = high_resolution_clock::now();
    PirQuery query = client.generate_query_combined(index);

    cout<<"Main: query size = "<< query.size()<< endl;

    //传给server
    GSWCiphertext enc_sk=client.get_enc_sk();


    auto time_query_e = high_resolution_clock::now();
    auto time_query_us = duration_cast<microseconds>(time_query_e - time_query_s).count();
    cout << "Main: query generated" << endl;
    //从server获取reply
}
