#include "common.h"

uint32_t N=4096;
uint32_t logt=60;
uint64_t size_per_item=23;
uint32_t number_of_groups=90;
string ip = "127.0.0.1";
int port = 11111;
bool process_data=false;
bool process_split_db=false;
bool use_memory_db=false;
float max_memory_db_size=12.0; // 单位为GB