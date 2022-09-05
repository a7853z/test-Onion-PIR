#include "db_center.h"
#include "common.h"
#include "external_prod.h"
#include <iostream>
#include <fstream>

DbCenter::DbCenter() {
    db_groups = new Db_t[number_of_groups];
}

DbCenter::~DbCenter() {
    for (uint32_t i = 0; i < number_of_groups; i++) {
        release_db(i);
    }
    delete []db_groups;
}

void DbCenter::release_db(uint32_t id_mod) {
    Db_t &db = db_groups[id_mod];
    size_t size1 = db.size();
    for (size_t i = 0; i < size1; i++) {
        size_t size2 = db[i].size();
        for (size_t j = 0; j < size2; j++) {
            free(db[i][j]);
        }
    }
    db.clear();
}

Db_t DbCenter::get_db(uint32_t id_mod) {
    Db_t ret;
    if (id_mod < 0 || id_mod >= number_of_groups) return ret;
    {
        lock_guard<mutex> lock(db_mutex);
        ret = db_groups[id_mod];
    }
    // TODO 最大内存限制
    if (ret.empty()) {
        cout << "empty db!!!!!!!!" << endl;
        auto time_pre_s = high_resolution_clock::now();
        ret = read_split_db_from_disk(id_mod);
        auto time_pre_e = high_resolution_clock::now();
        auto time_pre_us = duration_cast<microseconds>(time_pre_e - time_pre_s).count();
        cout << "read from disk time:" << time_pre_us / 1000 << " ms" << endl;
        {
            lock_guard<mutex> lock(db_mutex);
            db_groups[id_mod] = ret;
        }
    } else {
        cout << "cache!!!!!!!!!!!!" << endl;
    }
    return ret;
}

Db_t DbCenter::read_split_db_from_disk(uint32_t id_mod) {
    char split_db_file[40];
    sprintf(split_db_file, "split_db/split_db_%d.bin", id_mod);

    ifstream is(split_db_file, ios::binary | ios::in);
    size_t size1;
    Db_t results;
    is.read(reinterpret_cast<char*>(&size1), streamsize(sizeof(size_t)));
    for (size_t i = 0; i < size1; i++) {
        size_t size2;
        is.read(reinterpret_cast<char*>(&size2), streamsize(sizeof(size_t)));
        vector<uint64_t *> result;
        for (size_t j = 0; j < size2; j++) {
            uint64_t *res = (uint64_t *) calloc((poly_t::nmoduli * poly_t::degree),
                                                          sizeof(uint64_t));
            is.read(reinterpret_cast<char*>(res),
                    streamsize(poly_t::nmoduli * poly_t::degree * sizeof(uint64_t)));
            result.push_back(res);
        }
        results.push_back(result);
    }
    is.close();
    return results;
}