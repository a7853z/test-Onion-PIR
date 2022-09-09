//
// Created by AAGZ0452 on 2022/8/26.
//

#ifndef ONIONPIR_COMMON_H
#define ONIONPIR_COMMON_H

#include "SHA256.h"

#include <string>
using namespace std;

extern uint32_t N;
extern uint32_t logt;
extern uint64_t size_per_item;
extern uint32_t number_of_groups;
extern string ip;
extern int port;
extern bool process_data;
extern bool process_split_db;
extern bool use_memory_db;
extern float max_memory_db_size;
extern string batch_id_file;
extern string id_file;
extern string data_file;
extern uint32_t batch_id_number;
extern bool batch_id_preprocess;

inline uint32_t get_id_mod(string query_id, uint32_t number_of_groups)
{
    SHA256 sha;
    sha.update(query_id);
    uint8_t * digest = sha.digest();
    uint32_t id_mod = SHA256::mod(digest, number_of_groups);
    //cout << SHA256::toString(digest) << " mod:"<<id_mod<<std::endl;
    delete[] digest;
    return id_mod;
}
#endif //ONIONPIR_COMMON_H