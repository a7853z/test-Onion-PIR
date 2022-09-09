#include "db_center.h"
#include "common.h"
#include "external_prod.h"
#include <iostream>
#include <fstream>

static const size_t MAX_HIT_SEQ = 1000000000;

DbCenter::DbCenter():total_size(0), hit_seq(0) {
    db_groups = new DbData[number_of_groups];
}

DbCenter::~DbCenter() {
    for (uint32_t i = 0; i < number_of_groups; i++) {
        release_db(i);
    }
    delete []db_groups;
}

// 保证hit_seq不溢出
void DbCenter::ensure_valid_hit_seq(uint32_t id_mod) {
    if (db_groups[id_mod].hit_seq < MAX_HIT_SEQ) return;
    for (uint32_t i = 0; i < number_of_groups; i++) {
        if (i != id_mod) db_groups[i].hit_seq = 0;
    }
    hit_seq = 0;
    db_groups[id_mod].hit_seq = ++hit_seq; 
}

// 保证内存不超过最大值
void DbCenter::ensure_valid_memory_size(uint32_t id_mod) {
    uint32_t min_id_mod;
    uint32_t min_hit_seq;
    while (total_size / 1024.0 / 1024.0 / 1024.0 > max_memory_db_size) {
        min_id_mod = -1;
        min_hit_seq = MAX_HIT_SEQ;
        for (uint32_t i = 0; i < number_of_groups; i++) {
            if (id_mod == i) continue;
            if (db_groups[i].db.empty()) continue;
            if (db_groups[i].size == 0) continue;
            if (db_groups[i].hit_seq < min_hit_seq) {
                min_hit_seq = db_groups[i].hit_seq;
                min_id_mod = i;
            }
        }
        if (min_id_mod == -1) break;
        release_db(min_id_mod);
    }
}

void DbCenter::release_db(uint32_t id_mod) {
    Db_t &db = db_groups[id_mod].db;
    size_t size1 = db.size();
    for (size_t i = 0; i < size1; i++) {
        size_t size2 = db[i].size();
        for (size_t j = 0; j < size2; j++) {
            free(db[i][j]);
        }
    }
    db.clear();
    cout << "release db: " << id_mod << endl;
    cout << "before size: " << total_size / 1024.0 / 1024.0 / 1024.0 << endl;
    total_size -= db_groups[id_mod].size;
    cout << "before size: " << total_size / 1024.0 / 1024.0 / 1024.0 << endl;
    db_groups[id_mod].size = 0;
    db_groups[id_mod].hit_seq = 0;
}

Db_t DbCenter::get_db(uint32_t id_mod) {
    Db_t ret;
    if (id_mod < 0 || id_mod >= number_of_groups) return ret;
    {
        lock_guard<mutex> lock(db_mutex);
        ret = db_groups[id_mod].db;
        db_groups[id_mod].hit_seq = ++hit_seq;
        ensure_valid_hit_seq(id_mod);
    }
    if (ret.empty()) {
        size_t size;
        ret = read_split_db_from_disk(id_mod, &size);
        {
            lock_guard<mutex> lock(db_mutex);
            db_groups[id_mod].db = ret;
            db_groups[id_mod].size = size;
            db_groups[id_mod].hit_seq = ++hit_seq;
            total_size += size;
            ensure_valid_hit_seq(id_mod);
            ensure_valid_memory_size(id_mod);
        }
    }

    return ret;
}

Db_t DbCenter::read_split_db_from_disk(uint32_t id_mod, size_t* ret_size) {
    char split_db_file[40];
    sprintf(split_db_file, "split_db/split_db_%d.bin", id_mod);

    size_t total = 0;

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
            auto len = streamsize(poly_t::nmoduli * poly_t::degree * sizeof(uint64_t));
            is.read(reinterpret_cast<char*>(res), len);
            total += len;
            result.push_back(res);
        }
        results.push_back(result);
    }
    is.close();

    if (ret_size) *ret_size = total;

    return results;
}