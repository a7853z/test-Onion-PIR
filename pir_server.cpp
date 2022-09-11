
//
// Created by Haris Mughees on 4/21/21.
//

#include "pir_server.h"
#include "db_center.h"


pir_server::pir_server(const EncryptionParameters &params, const PirParams &pir_params) :
        params_(params),
        pir_params_(pir_params),
        is_db_preprocessed_(false)
{
    auto context = SEALContext::Create(params, false);
    evaluator_ = make_unique<Evaluator>(context);
    seal::GaloisKeys galkey;
    parms_id_= context->first_parms_id();
    newcontext_ = SEALContext::Create(params_);

}

void pir_server::set_galois_key(uint32_t client_id, seal::GaloisKeys galkey) {
    //galkey.parms_id() = parms_id_;
    galoisKeys_ = galkey;

}

//数据转换成plaintext的d维plaintext矩阵  plaintext或矩阵缺失的系数用1填充
void
pir_server::set_database(const unique_ptr<const uint8_t[]> &bytes, uint64_t ele_num, uint64_t ele_size) {
    u_int64_t logt = params_.plain_modulus().bit_count();
    uint32_t N = params_.poly_modulus_degree();
    // number of FV plaintexts needed to represent all elements
    uint64_t total = plaintexts_per_db(logt, N, ele_num, ele_size);



    // number of FV plaintexts needed to create the d-dimensional matrix
    uint64_t prod = 1;
    for (uint32_t i = 0; i < pir_params_.nvec.size(); i++) {
        //cout<<"nevc["<<i<<"]:"<<pir_params_.nvec[i]<<endl;
        prod *= pir_params_.nvec[i];
        //cout<<"prod:"<<prod<<endl;
    }



    uint64_t matrix_plaintexts = prod;
    assert(total <= matrix_plaintexts);

    auto result = make_unique<vector<Plaintext>>();
    result->reserve(matrix_plaintexts);

    // N/coefficients_per_element
    uint64_t ele_per_ptxt = elements_per_ptxt(logt, N, ele_size);

    uint64_t bytes_per_ptxt = ele_per_ptxt * ele_size;

    uint64_t db_size = ele_num * ele_size;

    //=N
    uint64_t coeff_per_ptxt = ele_per_ptxt * coefficients_per_element(logt, ele_size);

    cout<<"total==>"<< logt <<endl;
    assert(coeff_per_ptxt <= N);

    cout << "Server: total number of FV plaintext = " << total << endl;
    cout << "Server: elements packed into each plaintext " << ele_per_ptxt << endl;

    uint32_t offset = 0;

    for (uint64_t i = 0; i < total; i++) {
        uint64_t process_bytes = 0;


        if (db_size <= offset) {
            break;
        } else if (db_size < offset + bytes_per_ptxt) {
            process_bytes = db_size - offset;
        } else {
            process_bytes = bytes_per_ptxt;
        }

        // Get the coefficients of the elements that will be packed in plaintext i
//        bytes_to_coeffs(uint32_t limit, const uint64_t *bytes,
//        uint64_t size);




        vector<uint64_t> coefficients = bytes_to_coeffs(logt, bytes.get() + offset, process_bytes);
            offset += process_bytes;

        uint64_t used = coefficients.size();

        assert(used <= coeff_per_ptxt);

        // Pad the rest with 1s
        for (uint64_t j = 0; j < (N - used); j++) {
            coefficients.push_back(1);
        }
//
        Plaintext plain;
        vector_to_plaintext(coefficients, plain);
        //cout << i << "-th encoded plaintext = " << plain.to_string() << endl;
        result->push_back(move(plain));
    }


    // Add padding to make database a matrix
    uint64_t current_plaintexts = result->size();
    assert(current_plaintexts <= total);
//
#ifdef DEBUG
    cout << "adding: " << matrix_plaintexts - current_plaintexts
         << " FV plaintexts of padding (equivalent to: "
         << (matrix_plaintexts - current_plaintexts) * elements_per_ptxt(logtp, N, ele_size)
         << " elements)" << endl;
#endif
    //cout<<"begin padding, matrix number:"<<matrix_plaintexts<<" current number:"<< current_plaintexts<<endl;
    vector<uint64_t> padding(N, 1);

    for (uint64_t i = 0; i < (matrix_plaintexts - current_plaintexts); i++) {
        Plaintext plain;
        vector_to_plaintext(padding, plain);
        result->push_back(plain);
    }

    cout<<"set server's db"<<endl;
    set_database(move(result));
}

// Server takes over ownership of db and will free it when it exits
void pir_server::set_database(unique_ptr<vector<Plaintext>> &&db) {
    if (!db) {
        throw invalid_argument("db cannot be null");
    }

    db_ = move(db);
}




PirReply pir_server::generate_reply_combined(PirQuery query, uint32_t client_id) {

    assert(query.size()==2);

    auto Total_start  = high_resolution_clock::now();

    Plaintext pt;
    pt.resize(4096);
    pt.set_zero();
    //pt[0]=123;

    vector<uint64_t> nvec = pir_params_.nvec;


    uint64_t product = 1;

    for (uint32_t i = 0; i < nvec.size(); i++) {
        product *= nvec[i];

    }


    vector<Plaintext> intermediate_plain; // decompose....

    auto pool = MemoryManager::GetPool();


    int N = params_.poly_modulus_degree();

    int logt = params_.plain_modulus().bit_count();

    vector<Ciphertext> first_dim_intermediate_cts(product/nvec[0]);


    for (uint32_t i = 0; i < 1; i++) {

        uint64_t n_i = nvec[i];
        cout << "Server: first dimension size  = " << n_i << endl;


        uint64_t total = n_i;



        vector<GSWCiphertext> list_enc;

        int decomp_size = params_.plain_modulus().bit_count() / pir_params_.plain_base;
        list_enc.resize(n_i, GSWCiphertext(decomp_size));
        vector<GSWCiphertext>::iterator list_enc_ptr = list_enc.begin();
        auto start = high_resolution_clock::now();

        //vector<Ciphertext> expanded_query_part = expand_query(query[i][j], total, client_id);

        //n_1=64   应该是n_0，值应该是256
        poc_expand_flat_combined(list_enc_ptr, query[i], newcontext_, n_i, galoisKeys_);





        //cout << "Server: expansion done " << endl;
        // cout << " size mismatch!!! " << expanded_query.size() << ", " << n_i << endl;
        if (list_enc.size() != n_i) {
            cout << " size mismatch!!! " << list_enc.size() << ", " << n_i << endl;
        }

        for (uint32_t jj = 0; jj < list_enc.size(); jj++)
        {
            poc_nfllib_ntt_gsw(list_enc[jj],newcontext_);
        }

        auto end = high_resolution_clock::now();
        int time_server_us =  duration_cast<milliseconds>(end - start).count();
        cout<<"Server: rlwe exansion time = "<<time_server_us<<" ms"<<endl;


        product /= n_i;

        vector<Ciphertext> intermediateCtxts(product);





        int durrr =0;

        auto expand_start = high_resolution_clock::now();
        for (uint64_t k = 0; k < product; k++) {

            first_dim_intermediate_cts[k].resize(newcontext_, newcontext_->first_context_data()->parms_id(), 2);
            poc_nfllib_external_product(list_enc[0], split_db[k], newcontext_, decomp_size, first_dim_intermediate_cts[k],1);

            for (uint64_t j = 1; j < n_i; j++) {

                uint64_t total = n_i;

                //cout << "-- expanding one query ctxt into " << total  << " ctxts "<< endl;


                Ciphertext temp;
                temp.resize(newcontext_, newcontext_->first_context_data()->parms_id(), 2);


                poc_nfllib_external_product(list_enc[j], split_db[k + j * product], newcontext_, decomp_size, temp,1);


                evaluator_->add_inplace(first_dim_intermediate_cts[k], temp); // Adds to first component.
                //poc_nfllib_add_ct(first_dim_intermediate_cts[k], temp,newcontext_);

                //cout << "first-dimension cost" << durrr  << endl;


            }

        }

        auto expand_end  = high_resolution_clock::now();

        durrr =duration_cast<milliseconds>(expand_end - expand_start).count();
        cout << "Server: first-dimension mul cost = " << durrr << " ms" << endl;



        expand_start  = high_resolution_clock::now();

        for (uint32_t jj = 0; jj < first_dim_intermediate_cts.size(); jj++) {


            //evaluator_->transform_from_ntt_inplace(intermediateCtxts[jj]);
            poc_nfllib_intt_ct(first_dim_intermediate_cts[jj],newcontext_);

        }

        expand_end  = high_resolution_clock::now();
        durrr =  duration_cast<milliseconds>(expand_end - expand_start).count();
        cout << "Server: INTT after first dimension = " << durrr << " ms" << endl;


    }


    uint64_t  new_dimension_size=0, logsize;
    if(nvec.size()>1) {

        for (uint32_t i = 1; i < nvec.size(); i++) {
            new_dimension_size = new_dimension_size + nvec[i];
        }

//        logsize = ceil(log2(new_dimension_size));


    }

    //testing starts from here
    vector<GSWCiphertext> CtMuxBits;
    int total_dim_size = new_dimension_size;

    logsize = ceil(log2(total_dim_size*pir_params_.gsw_decomp_size));


    //int decomp_size = newcontext_->first_context_data()->total_coeff_modulus_bit_count() / pir_params_.gsw_base;
    int decomp_size = pir_params_.gsw_decomp_size ;
    int sk_decomp_size = newcontext_->first_context_data()->total_coeff_modulus_bit_count() / pir_params_.secret_base;
    CtMuxBits.resize(total_dim_size, GSWCiphertext(2 * decomp_size));
    vector<GSWCiphertext>::iterator gswCiphers_ptr = CtMuxBits.begin();


    //thread_server_expand(gswCiphers_ptr, query[1], newcontext_, 0, decomp_size, size, galoisKeys_,  decomp_size, pir_params_.gsw_base, sk_decomp_size, pir_params_.secret_base, sk_enc_);

    auto expand_start  = high_resolution_clock::now();

    gsw_server_expand_combined(gswCiphers_ptr, query[1], newcontext_, 0, decomp_size, total_dim_size, galoisKeys_,  decomp_size, pir_params_.gsw_base, sk_decomp_size, pir_params_.secret_base, sk_enc_, 1<<logsize);

    for (uint32_t jj = 0; jj < CtMuxBits.size(); jj++)
    {
        poc_nfllib_ntt_gsw(CtMuxBits[jj],newcontext_);
    }


    auto expand_end  = high_resolution_clock::now();
    uint64_t durrr =  duration_cast<milliseconds>(expand_end - expand_start).count();
    cout << "Server: expand after first diemension = " << durrr << " ms" << endl;

    auto remaining_start = chrono::high_resolution_clock::now();
    //for remaining dimensions we treat them differently
    uint64_t  previous_dim=0;
    for (uint32_t i = 1; i < nvec.size(); i++){

        uint64_t n_i = nvec[i];

        product /= n_i;
        vector<Ciphertext> intermediateCtxts(product);//output size of this dimension




        for (uint64_t k = 0; k < product; k++) {


            intermediateCtxts[k].resize(newcontext_, newcontext_->first_context_data()->parms_id(), 2);
            vector<uint64_t *> rlwe_decom;
            rwle_decompositions(first_dim_intermediate_cts[k], newcontext_, decomp_size, pir_params_.gsw_base, rlwe_decom);
            poc_nfllib_ntt_rlwe_decomp(rlwe_decom);
            poc_nfllib_external_product(CtMuxBits[0 + previous_dim], rlwe_decom, newcontext_, decomp_size, intermediateCtxts[k],1);
            for (auto p : rlwe_decom) {
                free(p);
            }

            for (uint64_t j = 1; j < n_i; j++) {


                Ciphertext temp;
                rlwe_decom.clear();
                rwle_decompositions(first_dim_intermediate_cts[k + j * product], newcontext_, decomp_size, pir_params_.gsw_base, rlwe_decom);
                poc_nfllib_ntt_rlwe_decomp(rlwe_decom);
                temp.resize(newcontext_, newcontext_->first_context_data()->parms_id(), 2);
                poc_nfllib_external_product(CtMuxBits[j + previous_dim], rlwe_decom, newcontext_, decomp_size, temp,1);

                for (auto p : rlwe_decom) {
                    free(p);
                }
                evaluator_->add_inplace(intermediateCtxts[k], temp); // Adds to first component.



            }

        }



        for (uint32_t jj = 0; jj < intermediateCtxts.size(); jj++) {

            poc_nfllib_intt_ct(intermediateCtxts[jj],newcontext_);

        }

        first_dim_intermediate_cts.clear();
        first_dim_intermediate_cts=intermediateCtxts;
        previous_dim=previous_dim+n_i;

    }


    auto remaining_end  = high_resolution_clock::now();
     durrr =  duration_cast<milliseconds>(remaining_end - remaining_start).count();
     cout << "Server: remaining-dimensions dot-products = " << durrr << " ms" << endl;



    auto Total_end  = high_resolution_clock::now();
    durrr =  duration_cast<milliseconds>(Total_end - Total_start).count();
//    cout << "Total" << durrr  << endl;

    return first_dim_intermediate_cts;
}



void pir_server::preprocess_database() {
    // 60/30
    //split_db.clear();
    clear_split_db();
    int decomp_size = params_.plain_modulus().bit_count() / pir_params_.plain_base;
    for (uint32_t i = 0; i < db_->size(); i++) {

        vector<uint64_t *> plain_decom;
        plain_decompositions(db_->data()[i], newcontext_, decomp_size, pir_params_.plain_base, plain_decom);
        poc_nfllib_ntt_rlwe_decomp(plain_decom);
        split_db.push_back(plain_decom);
    }
}

// 将split_db写到文件中
void pir_server::write_split_db2disk(char * split_db_file) {
    ofstream os(split_db_file, ios::binary | ios::out);
    size_t size1 = split_db.size();
    os.write(reinterpret_cast<char*>(&size1), streamsize(sizeof(size_t)));
    for (size_t i = 0; i < size1; i++) {
        size_t size2 = split_db[i].size();
        os.write(reinterpret_cast<char*>(&size2), streamsize(sizeof(size_t)));
        for (size_t j = 0; j < size2; j++) {
            uint64_t *p = split_db[i][j];
            os.write(reinterpret_cast<char*>(p),
                     streamsize(sizeof(uint64_t)*poly_t::nmoduli*poly_t::degree));
        }
    }
    os.close();
}

void pir_server::read_split_db_from_disk(uint32_t id_mod) {
    clear_split_db();
    split_db = DbCenter::read_split_db_from_disk(id_mod);
}

void pir_server::read_split_db_from_cache(uint32_t id_mod) {
    split_db = DbCenter::get_instance().get_db(id_mod);
}

// 清空split_db
void pir_server::clear_split_db() {
    size_t size1 = split_db.size();
    for (size_t i = 0; i < size1; i++) {
        size_t size2 = split_db[i].size();
        for (size_t j = 0; j < size2; j++) {
            free(split_db[i][j]);
        }
    }
    split_db.clear();
}

void pir_server::set_enc_sk(GSWCiphertext sk_enc) {
    sk_enc_=sk_enc;
}

void pir_server::updata_pir_params(const PirParams &pir_parms) {
    pir_params_ = pir_parms;
}
