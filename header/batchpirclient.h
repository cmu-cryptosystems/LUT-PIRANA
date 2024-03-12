#ifndef BATCHPIRCLIENT_H
#define BATCHPIRCLIENT_H


#include "batchpirparams.h"
#include "utils.h"
#include "client.h"
#include <seal/galoiskeys.h>
#include <seal/serializable.h>
#include <seal/util/defines.h>

using namespace std;

class BatchPIRClient {
public:
    BatchPIRClient(const BatchPirParams& params);
    vector<vector<PIRQuery>> create_queries(vector<vector<string>> batch);
    vector<EncodedDB> decode_responses(vector<PIRResponseList> responses);

    std::pair<vector<seal_byte>, vector<seal_byte>> get_public_keys();
    size_t get_serialized_commm_size();
    
    std::vector<vector<uint64_t>> bucket_to_position;
    // bucket index to query index
    std::unordered_map<uint64_t, uint64_t> cuckoo_map;
    // query index to bucket index
    std::unordered_map<uint64_t, uint64_t> inv_cuckoo_map;;

    // serialization support
    inline auto serialize_query(vector<vector<PIRQuery>> queries) {
        vector<vector<vector<vector<seal_byte>>>> buffer(batchpir_params_.query_size[0]);
        for (int i = 0; i < batchpir_params_.query_size[0]; i++) {
            buffer[i].resize(batchpir_params_.query_size[1]);
            for (int j = 0; j < batchpir_params_.query_size[1]; j++) {
                buffer[i][j].resize(batchpir_params_.query_size[2]);
                for (int k = 0; k < batchpir_params_.query_size[2]; k++) {
                    auto& ct = queries[i][j][k];
                    size_t save_size = ct.save_size();
                    buffer[i][j][k].resize(save_size);
                    auto actual_size = ct.save(buffer[i][j][k].data(), save_size);
                    buffer[i][j][k].resize(actual_size);
                    serialized_comm_size_ += actual_size;
                }
            }
        }
        return buffer;
    }
    
    inline vector<PIRResponseList> deserialize_response(vector<vector<vector<seal_byte>>> responses_buffer) {
        vector<PIRResponseList> responses(batchpir_params_.response_size[0]);
        for (int i = 0; i < batchpir_params_.response_size[0]; i++) {
            responses[i].resize(batchpir_params_.response_size[1]);
            for (int j = 0; j < batchpir_params_.response_size[1]; j++) {
                responses[i][j].load(*context_, responses_buffer[i][j].data(), responses_buffer[i][j].size());
                serialized_comm_size_ += responses_buffer[i][j].size();
            }
        }
        return responses;
    }

private:
    BatchPirParams batchpir_params_;
    size_t max_attempts_;
    bool is_cuckoo_generated_;
    size_t serialized_comm_size_ = 0;
    
    vector<vector<Client>> client_list_;

    seal::SEALContext* context_;
    seal::KeyGenerator* keygen_;
    seal::SecretKey secret_key_;
    seal::Encryptor* encryptor_;
    seal::Decryptor* decryptor_;
    seal::BatchEncoder* batch_encoder_;
    seal::GaloisKeys gal_keys_;
    seal::RelinKeys relin_keys_;

    vector<seal_byte> glk_buffer, rlk_buffer;

    void measure_size(vector<Ciphertext> list, size_t seeded = 1);
    bool cuckoo_hash(vector<vector<string>> batch);
    void prepare_pir_clients();
};

#endif // BATCHPIRCLIENT_H
