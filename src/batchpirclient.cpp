#include "batchpirclient.h"
#include <cstdint>
#include <seal/ciphertext.h>
#include <seal/evaluator.h>
#include <seal/plaintext.h>
#include <stdexcept>
#include <sys/types.h>

BatchPIRClient::BatchPIRClient(const BatchPirParams &params)
    : batchpir_params_(params), is_cuckoo_generated_(false)
{
    max_attempts_ = batchpir_params_.get_max_attempts();

    prepare_pir_clients();
}

vector<PIRQuery> BatchPIRClient::create_queries(vector<vector<string>> batch)
{

    if (batch.size() != batchpir_params_.get_batch_size())
        throw std::runtime_error("Error: batch is not selected size");

    cuckoo_hash(batch);

    size_t batch_size = batchpir_params_.get_batch_size();
    size_t bucket_size = batchpir_params_.get_bucket_size();
    size_t entry_size = batchpir_params_.get_entry_size();
    size_t w = batchpir_params_.get_num_hash_funcs();
    auto max_slots = batchpir_params_.get_seal_parameters().poly_modulus_degree();
    auto num_buckets = batchpir_params_.get_num_buckets();

    const size_t m = DatabaseConstants::PIRANA_m;
    
    Plaintext pt;
    Ciphertext ct;

    vector<PIRQuery> queries(w, PIRQuery(m));
    // queries[1..w][1..m] is a ciphertext
    // Push the batch into the queries
    for (int i = 0; i < w; i++)
    {
        vector<vector<uint64_t>> q(m, vector<uint64_t>(num_buckets));
        vector<vector<uint64_t>> codes(num_buckets);
        for (int j = 0; j < num_buckets; j++)
        {
            codes[j] = utils::get_perfect_constant_weight_codeword(bucket_to_position[j][i], m, DatabaseConstants::PIRANA_k);
            for (int k = 0; k < m; k++) {
                q[k][j] = codes[j][k];
            }
        }

        for (int k = 0; k < m; k++) {
            batch_encoder_->encode(q[k], pt);
            encryptor_->encrypt_symmetric(pt, queries[i][k]);
        }

        // check
        #ifdef DEBUG 
        cout << "checking queries" << endl;
        #pragma omp parallel for
        for (int column = 0; column < bucket_size; column++) {
            auto code = utils::get_perfect_constant_weight_codeword(column, m, DatabaseConstants::PIRANA_k);
            vector<uint64_t> q;
            for (int k = 0; k < m; k++) {
                if (code[k]) q.push_back(k);
            }
            Ciphertext prod;
            evaluator_->multiply(queries[i][q[0]], queries[i][q[1]], prod);
            Plaintext pt;
            decryptor_->decrypt(prod, pt);
            vector<uint64_t> result;
            batch_encoder_->decode(pt, result);
            for (int row = 0; row < num_buckets; row++) {
                if (result[row] != (bucket_to_position[row][i] == column)) {
                    throw std::runtime_error(fmt::format("Error: {} {} {}", i, column, row));
                }
            }
        }
        #endif
    }

    for(auto& q: queries) {
        measure_size(q);
    }

    return queries;
}


// batch contains the hash values
bool BatchPIRClient::cuckoo_hash(vector<vector<string>> batch)
{

    size_t total_buckets = batchpir_params_.get_num_buckets();
    auto db_entries = batchpir_params_.get_num_entries();
    auto num_candidates = batchpir_params_.get_num_hash_funcs();
    size_t bucket_size = batchpir_params_.get_bucket_size();
    auto attempts = batchpir_params_.get_max_attempts();
    auto batch_size = batchpir_params_.get_batch_size();
    size_t w = batchpir_params_.get_num_hash_funcs();

    if (batch.size() != batch_size)
    {
        cout << batch.size() << " " << batch_size << " " << endl;
        throw std::invalid_argument("Error: Batch size is wrong");
    }

    std::unordered_map<uint64_t, std::vector<uint64_t>> key_to_buckets(batch_size);
    std::unordered_map<uint64_t, std::vector<uint64_t>> key_to_position(batch_size);
    
    for (int i = 0; i < batch_size; i++)
    {
        auto [candidate_buckets, candidate_positions]  = utils::get_candidates_with_hash_values(total_buckets, bucket_size, batch[i]);
        key_to_buckets[i] = candidate_buckets;
        key_to_position[i] = candidate_positions;
    }

    // seed the random number generator with current time
    // srand(time(nullptr));
    for (auto const &[key, value] : key_to_buckets)
    {
        utils::cuckoo_insert(key, 0, key_to_buckets, cuckoo_map);
    }
    
    bucket_to_position.resize(total_buckets, vector<uint64_t>(w, batchpir_params_.get_default_value()));
    for (auto const &[key, value] : cuckoo_map)
    {
        bucket_to_position[key] = key_to_position[value];
        inv_cuckoo_map[value] = key;
    }

    is_cuckoo_generated_ = true;

    return true;
}

void BatchPIRClient::measure_size(vector<Ciphertext> list, size_t seeded){
    for (int i=0; i < list.size(); i++){
        serialized_comm_size_ += ceil(list[i].save_size()/seeded);
    }
}

size_t BatchPIRClient::get_serialized_commm_size(){
    return ceil((double)serialized_comm_size_/1024);
}


void BatchPIRClient::prepare_pir_clients()
{
    context_ = new SEALContext(batchpir_params_.get_seal_parameters());
    batch_encoder_ = new BatchEncoder(*context_);
    keygen_ = new KeyGenerator(*context_);
    secret_key_ = keygen_->secret_key();
    encryptor_ = new Encryptor(*context_, secret_key_);
    decryptor_ = new Decryptor(*context_, secret_key_);
    // setting client's public keys
    keygen_->create_galois_keys(gal_keys_);
    keygen_->create_relin_keys(relin_keys_);

    #ifdef DEBUG 
    evaluator_ = new Evaluator(*context_);
    #endif
}

// return 1..w, 1..B
RawResponses BatchPIRClient::decode_responses(vector<PIRResponseList> responses, vector<prefixblock> nonces, vector<block> encryption_masks)
{
    cout << serialized_comm_size_ << endl;
    serialized_comm_size_ += nonces.size() * sizeof(prefixblock);
    auto plaint_bit_count_ = batchpir_params_.get_seal_parameters().plain_modulus().bit_count();
    size_t w = batchpir_params_.get_num_hash_funcs();
    const auto num_columns_per_entry = batchpir_params_.get_num_slots_per_entry();
    const int size_of_coeff = plaint_bit_count_ - 1;
    int entry_size = batchpir_params_.get_entry_size();
    size_t batch_size = batchpir_params_.get_batch_size();
    auto num_buckets = batchpir_params_.get_num_buckets();
    vector<vector<block>> entries_list(num_buckets, vector<block>(w));
    for (int hash_idx = 0; hash_idx < w; hash_idx++)
    {
        auto& response = responses[hash_idx];
        measure_size(response);

        vector<string> str_entries(num_buckets, "");
        for (int slot_idx = 0; slot_idx < num_columns_per_entry; slot_idx++)
        {
            size_t start = slot_idx * size_of_coeff;
            size_t end = std::min((slot_idx + 1) * size_of_coeff, entry_size);
            vector<uint64_t> plain_entry(num_buckets);
            Plaintext pt;
            decryptor_->decrypt(response[slot_idx], pt);
            batch_encoder_->decode(pt, plain_entry);
            for (int bucket_idx = 0; bucket_idx < num_buckets; bucket_idx++) {
                str_entries[bucket_idx] += block(plain_entry[bucket_idx]).to_string().substr(blocksize-(end - start));
            }
        }
        for (int bucket_idx = 0; bucket_idx < num_buckets; bucket_idx++) {
            if (cuckoo_map.count(bucket_idx)) {
                entries_list[bucket_idx][hash_idx] = block(str_entries[bucket_idx]) ^ encryption_masks[cuckoo_map[bucket_idx]];
            }
        }
        // Unmask
        #ifdef DEBUG 
        cout << fmt::format("query {}: Unmask {} with {} -> {}", hash_idx, str_entries[server->iB_of_interest], encryption_masks[cuckoo_map.at(server->iB_of_interest)].to_string(), entries_list[server->iB_of_interest][hash_idx].to_string()) << endl;
        #endif
    }

    // Unmasking and Nonce matching
    RawResponses raw_responses(num_buckets);
    for (int batch_idx = 0; batch_idx < batch_size; batch_idx++) {
        bool flag = false;
        auto bucket_idx = inv_cuckoo_map[batch_idx];
        for (int hash_idx = 0; hash_idx < w; hash_idx++) {
            auto [prefix, data_item] = utils::split(entries_list[bucket_idx][hash_idx]);
            if (prefix == nonces[bucket_idx]) {
                if (flag) {
                    throw std::runtime_error("Error: Nonce matched more than once");
                } else {
                    raw_responses[bucket_idx] = data_item;
                    flag = true;
                }
            }
        }
        if (!flag) {
            throw std::runtime_error(fmt::format("Error: Nonce not matched for {}", bucket_idx));
        }
    }
    
    return raw_responses;
}

std::pair<GaloisKeys, RelinKeys> BatchPIRClient::get_public_keys()
{
    return std::make_pair(gal_keys_, relin_keys_);
}