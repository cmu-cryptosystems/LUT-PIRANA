#ifndef BATCHPIR_SERVER_H
#define BATCHPIR_SERVER_H

#include "batchpirparams.h"
#include "LowMC.h"
#include "src/utils.h"
#include "server.h"
#include <cstdint>
#include <seal/ciphertext.h>
#include <seal/decryptor.h>
#include <seal/plaintext.h>
#include <sys/types.h>
#include "database_constants.h"


class BatchPIRServer {

public:
    
    BatchPIRServer( BatchPirParams& batchpir_params);
    // std::unordered_map<std::string, uint64_t> get_hash_map() const;
    void set_client_keys(uint32_t client_id, std::pair<seal::GaloisKeys, seal::RelinKeys> keys);
    void get_client_keys();
    vector<PIRResponseList> generate_response(uint32_t client_id, vector<vector<PIRQuery>> queries);
    bool check_decoded_entries(vector<EncodedDB> entries_list, vector<rawdatablock>& queries, std::unordered_map<uint64_t, uint64_t> cuckoo_map);

    void initialize();
    void prepare_pir_server();
   
    std::vector<LowMC> ciphers;
    std::array<std::vector<rawdatablock>, DatabaseConstants::NumHashFunctions> index_masks, entry_masks;
    std::array<std::vector<size_t>, 1 << DatabaseConstants::OutputLength> candidate_buckets_array;
    std::array<std::vector<size_t>, 1 << DatabaseConstants::OutputLength> candidate_positions_array;

#ifndef DEBUG 
private:
#endif
    BatchPirParams *batchpir_params_;
    RawDB rawdb_;
    array<vector<EncodedDB>, DatabaseConstants::NumHashFunctions> buckets_;
    array<vector<vector<Plaintext>>, DatabaseConstants::NumHashFunctions> encoded_columns; // column, slot
    bool lowmc_encoded;
    bool is_client_keys_set_;
    std::vector<std::unordered_map<uint64_t, uint64_t>> position_to_key;
    vector<PIRResponseList> masked_value;

    #ifdef DEBUG 
    std::array<Ciphertext, DatabaseConstants::NumHashFunctions> mq;
    std::array<PIRResponseList, DatabaseConstants::NumHashFunctions> mv;
    int i_of_interest;
    int iB_of_interest;
    vector<uint64_t> icol_of_interest;
    std::array<vector<uint64_t>, DatabaseConstants::NumHashFunctions> plain_col_of_interest;
    #endif

    void lowmc_prepare();
    void lowmc_encode();
    void lowmc_encrypt();
    void initialize_masks();
    void populate_raw_db();
    // void print_stats() const; 

    // HE
    seal::SEALContext *context_;
    seal::Evaluator *evaluator_;
    seal::BatchEncoder *batch_encoder_;
    std::map<uint32_t, std::pair<seal::GaloisKeys, seal::RelinKeys>> client_keys_;
    vector<std::pair<seal::GaloisKeys, seal::RelinKeys>> client_keys_2;
    size_t plaint_bit_count_;
    size_t polynomial_degree_;
    vector<size_t> pir_dimensions_;
    size_t row_size_;
    size_t gap_;
    PIRQuery query_; 
    size_t num_databases_;
    
    array<vector<Server>, DatabaseConstants::NumHashFunctions> server_list_;

};

#endif // BATCHPIR_SERVER_H
