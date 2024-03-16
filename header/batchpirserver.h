#ifndef BATCHPIR_SERVER_H
#define BATCHPIR_SERVER_H

#include "batchpirparams.h"
#include "LowMC.h"
#include "utils.h"
#include "server.h"
#include <cstdint>
#include <seal/ciphertext.h>
#include <seal/decryptor.h>
#include <seal/plaintext.h>
#include <sys/types.h>
#include "database_constants.h"
#include <functional>


class BatchPIRServer {

public:
    
    BatchPIRServer( BatchPirParams& batchpir_params);
    // std::unordered_map<std::string, uint64_t> get_hash_map() const;
    void set_client_keys(uint32_t client_id, std::pair<vector<seal_byte>, vector<seal_byte>> keys);
    void get_client_keys();
    vector<PIRResponseList> generate_response(uint32_t client_id, vector<vector<PIRQuery>> queries);
    bool check_decoded_entries(vector<EncodedDB> entries_list, vector<rawinputblock>& queries, std::unordered_map<uint64_t, uint64_t> cuckoo_map);

    void initialize();
    void populate_raw_db(std::function<rawdatablock(size_t)> generator = [](size_t i){return random_bitset<DatabaseConstants::OutputLength>(); });
   
    std::vector<utils::LowMC> ciphers;
    std::array<std::vector<rawinputblock>, DatabaseConstants::NumHashFunctions> index_masks;
    std::array<std::vector<rawdatablock>, DatabaseConstants::NumHashFunctions> entry_masks;
    std::vector<std::vector<size_t>> candidate_buckets_array;
    std::vector<std::vector<size_t>> candidate_positions_array;

    inline vector<vector<PIRQuery>> deserialize_query(vector<vector<vector<vector<seal_byte>>>> queries_buffer) {
        vector<vector<PIRQuery>> queries(batchpir_params_->query_size[0]);
        for (int i = 0; i < batchpir_params_->query_size[0]; i++) {
            queries[i].resize(batchpir_params_->query_size[1]);
            for (int j = 0; j < batchpir_params_->query_size[1]; j++) {
                queries[i][j].resize(batchpir_params_->query_size[2]);
                for (int k = 0; k < batchpir_params_->query_size[2]; k++) {
                    queries[i][j][k].load(*context_, queries_buffer[i][j][k].data(), queries_buffer[i][j][k].size());
                }
            }
        }
        return queries;
    }
    
    inline auto serialize_response(vector<PIRResponseList> responses) {
        vector<vector<vector<seal_byte>>> buffer(batchpir_params_->response_size[0]);
        for (int i = 0; i < batchpir_params_->response_size[0]; i++) {
            buffer[i].resize(batchpir_params_->response_size[1]);
            for (int j = 0; j < batchpir_params_->response_size[1]; j++) {
                auto& ct = responses[i][j];
                size_t save_size = ct.save_size();
                buffer[i][j].resize(save_size);
                auto actual_size = ct.save(buffer[i][j].data(), save_size);
                buffer[i][j].resize(actual_size);
            }
        }
        return buffer;
    }

private:
    BatchPirParams *batchpir_params_;
    RawDB rawdb_;
    array<vector<EncodedDB>, DatabaseConstants::NumHashFunctions> buckets_;
    array<vector<vector<Plaintext>>, DatabaseConstants::NumHashFunctions> encoded_columns; // column, slot
    bool is_db_populated;
    bool lowmc_encoded;
    bool is_client_keys_set_;
    std::vector<std::unordered_map<uint64_t, uint64_t>> position_to_key;
    vector<PIRResponseList> masked_value;

    void lowmc_prepare();
    void lowmc_encode();
    void lowmc_encrypt();
    void initialize_masks();
    void prepare_pir_server();
    // void print_stats() const; 

    // HE
    seal::SEALContext *context_;
    seal::Evaluator *evaluator_;
    seal::BatchEncoder *batch_encoder_;
    std::map<uint32_t, seal::RelinKeys> client_keys_;
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
