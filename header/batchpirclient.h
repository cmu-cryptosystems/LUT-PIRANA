#ifndef BATCHPIRCLIENT_H
#define BATCHPIRCLIENT_H


#include "batchpirparams.h"
#include "src/utils.h"
#include "client.h"
#ifdef DEBUG
#include "header/batchpirserver.h"
#endif

using namespace std;

class BatchPIRClient {
public:
    BatchPIRClient(const BatchPirParams& params);
    vector<vector<PIRQuery>> create_queries(vector<vector<string>> batch);
    RawDB decode_responses(vector<PIRResponseList> responses, vector<prefixblock> nonces, vector<block> encryption_masks);

    std::pair<seal::GaloisKeys, seal::RelinKeys> get_public_keys();
    size_t get_serialized_commm_size();
    
    std::vector<vector<uint64_t>> bucket_to_position;
    // bucket index to query index
    std::unordered_map<uint64_t, uint64_t> cuckoo_map;
    // query index to bucket index
    std::unordered_map<uint64_t, uint64_t> inv_cuckoo_map;

#ifndef DEBUG
private:
#endif
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

    #ifdef DEBUG 
    seal::Evaluator *evaluator_;
    BatchPIRServer *server;
    #endif

    void measure_size(vector<Ciphertext> list, size_t seeded = 1);
    bool cuckoo_hash(vector<vector<string>> batch);
    void prepare_pir_clients();
};

#endif // BATCHPIRCLIENT_H
