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

void process_datas(uint32_t number_of_groups){

    string id_file = "../query_data.csv";

    //一个数组，记录每个文件的index
    uint32_t * index = new uint32_t [90];
    for (int i = 0; i < 90; ++i) {
        index[i]=0;
    }

    ifstream query_data(id_file.c_str(), ifstream::in);

    ofstream write_map[number_of_groups];
    for (int i = 0; i < number_of_groups; ++i) {
        char path[40];
        sprintf(path, "data_map_%d.data", i);
        write_map[i].open(path, ofstream::out|ofstream::app);
    }

    string one_line;
    getline(query_data, one_line); //跳过首行‘id’
    while (getline(query_data, one_line)) {
        string one_id = one_line.substr(0, 18);
        string output = one_line.substr(19, oneline.length());
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
    count_data.open("count_data.data");
    for (int i = 0; i < number_of_groups; ++i) {
        count_data<< i << " " << index[i]<<endl;
    }
}

unique_ptr<uint8_t[]> load_data(uint32_t id_mod, uint32_t item_size, uint32_t &number_of_items){

    cout << "id_mod:" << id_mod << endl;

    // read count of mod_id's data file
    ifstream read_count;
    string mod, mod_count;
    uint32_t count;
    read_count.open("count_data.data", ifstream::in);
    while(read_count>>mod>>mod_count){
        if(id_mod == atoi(mod.c_str())){
            count = atoi(mod_count.c_str());
            break;
        }
    }
    number_of_items = count;
    read_count.close();

    //read data to db
    char path1[40];
    sprintf(path1, "data_map_%d.data", id_mod);
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


int main(){
    uint64_t number_of_items = 0;  //百万不可区分度， 具体需要从服务器获取
    uint64_t size_per_item = 23;       //每条记录需要的占用23字节
    uint32_t N = 4096;
    uint32_t number_of_groups = 90;

    //pre-process ids
    bool process_data = false;
    if(process_data) {
        process_datas();
    }

    // Recommended values: (logt, d) = (12, 2) or (8, 1).
    uint32_t logt = 60;
    PirParams pir_params;
    EncryptionParameters parms(scheme_type::BFV);
    set_bfv_parms(parms);   //N和logt在这里设置
    gen_params( number_of_items,  size_per_item, N, logt,
                pir_params);

    cout << "Main: Initializing server." << endl;
    pir_server server(parms, pir_params);

    uint32_t id_mod; //get from client

    auto db = load_data(id_mod, size_per_item, number_of_items);

    auto time_pre_s = high_resolution_clock::now();
    //convert db data to a vector of plaintext: covert to coefficients of polynomials first
    server.set_database(move(db), number_of_items, size_per_item);

    //plaintext decomposition
    server.preprocess_database();

    auto time_pre_e = high_resolution_clock::now();
    auto time_pre_us = duration_cast<microseconds>(time_pre_e - time_pre_s).count();
    cout << "Main: PIRServer pre-processing time: " << time_pre_us / 1000 << " ms" << endl;

    //get from the client
    GaloisKeys galois_keys;
    //get from the client
    GSWCiphertext enc_sk;//get from the client, for query unpacking get top l rows for GSW ciphertext

    server.set_galois_key(0, galois_keys); //0 represents id of a Client

    server.set_enc_sk(enc_sk);

    PirQuery query;//get from client

    auto time_server_s = high_resolution_clock::now();
    PirReply reply = server.generate_reply_combined(query, 0); // generate reply and remote it to client
    auto time_server_e = high_resolution_clock::now();
    auto time_server_us = duration_cast<microseconds>(time_server_e - time_server_s).count();

    cout << "Main: PIRServer reply generation time: " << time_server_us / 1000 << " ms"
         << endl;

}

