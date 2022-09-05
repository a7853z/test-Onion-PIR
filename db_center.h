#ifndef DB_CENTER_H
#define DB_CENTER_H

#include <vector>
#include <cstdint>
#include <mutex>
using namespace std;

typedef vector<vector<uint64_t *>> Db_t;

// split_db的缓存
class DbCenter {
    public:
        // 获取单例
        static DbCenter& get_instance() {
            static DbCenter db_center;
            return db_center;
        }
        // 获取db缓存或从磁盘中读取
        Db_t get_db(uint32_t id_mod);
        // 释放db缓存
        void release_db(uint32_t id_mod);
        // 从磁盘加载split_db
        static Db_t read_split_db_from_disk(uint32_t id_mod);
    private:
        DbCenter();
        ~DbCenter();
        Db_t* db_groups;
        mutex db_mutex;
};

#endif //DB_CENTER_H