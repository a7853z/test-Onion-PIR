//
// Created by AAGZ0452 on 2022/8/26.
//

#ifndef ONIONPIR_COMMON_H
#define ONIONPIR_COMMON_H

#endif //ONIONPIR_COMMON_H

#include "SHA256.h"

uint32_t N=4096;
uint32_t logt=60;
uint64_t size_per_item=23;
uint32_t number_of_groups=90;
string ip = "127.0.0.1";
int port = 11111;
bool process_data=false;
bool process_split_db=false;

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