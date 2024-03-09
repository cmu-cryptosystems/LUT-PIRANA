#include "batchpirclient.h"
#include <cassert>
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

vector<vector<PIRQuery>> BatchPIRClient::create_queries(vector<vector<string>> batch)
{

    if (batch.size() != batchpir_params_.get_batch_size())
        throw std::runtime_error("Error: batch is not selected size");

    cuckoo_hash(batch);

    size_t batch_size = batchpir_params_.get_batch_size();
    size_t bucket_size = batchpir_params_.get_bucket_size();
    size_t w = batchpir_params_.get_num_hash_funcs();
    auto max_slots = batchpir_params_.get_seal_parameters().poly_modulus_degree();
    auto num_buckets = batchpir_params_.get_num_buckets();
    size_t num_subbucket = DatabaseConstants::PolyDegree / num_buckets;
    size_t subbucket_size = ceil(bucket_size * 1.0 / num_subbucket);
    size_t dim_size = batchpir_params_.get_first_dimension_size();
    size_t per_server_capacity = max_slots / dim_size;
    size_t num_servers = ceil(num_buckets / per_server_capacity);
    auto type = batchpir_params_.get_type();

    const size_t m = DatabaseConstants::PIRANA_m;
    
    Plaintext pt;
    Ciphertext ct;

    vector<vector<PIRQuery>> queries(w);

    for (int hash_idx = 0; hash_idx < w; hash_idx++)
    {
        if (type == PIRANA) {
            queries[hash_idx].push_back(PIRQuery(m));
            // queries[1..w][1..m] is a ciphertext
            // Push the batch into the queries
            vector<vector<uint64_t>> q(m, vector<uint64_t>(num_buckets * num_subbucket, 0));
            vector<vector<uint64_t>> codes(num_buckets);
            for (int bucket_idx = 0; bucket_idx < num_buckets; bucket_idx++)
            {
                size_t subbucket_idx = bucket_to_position[bucket_idx][hash_idx] / subbucket_size;
                size_t offset = bucket_to_position[bucket_idx][hash_idx] % subbucket_size;
                codes[bucket_idx] = utils::get_perfect_constant_weight_codeword(offset, m, DatabaseConstants::PIRANA_k);
                for (int code_dim = 0; code_dim < m; code_dim++) {
                    q[code_dim][bucket_idx*num_subbucket + subbucket_idx] = codes[bucket_idx][code_dim];
                }
            }

            for (int code_dim = 0; code_dim < m; code_dim++) {
                batch_encoder_->encode(q[code_dim], pt);
                encryptor_->encrypt_symmetric(pt, queries[hash_idx][0][code_dim]);
            }

        } else {
            vector<PIRQuery> qs;
            auto previous_idx = 0;
            for (int i = 0; i < client_list_.size(); i++)
            {
                const size_t offset = std::min(per_server_capacity, num_buckets - previous_idx);
                vector<uint64_t> sub_buckets(offset, DatabaseConstants::DefaultVal);
                for (int bucket_idx = 0; bucket_idx < offset; bucket_idx++)
                {
                    sub_buckets[bucket_idx] = bucket_to_position[previous_idx + bucket_idx][hash_idx];
                }
                previous_idx += offset;
                auto query = client_list_[i][hash_idx].gen_query(sub_buckets);
                measure_size(query, 2);
                qs.push_back(query);
            }
            queries[hash_idx] = qs;
        }
    }

    for(auto& qs: queries) {
        for (auto& q: qs) {
            measure_size(q, 2);
        }
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
    for (auto const &[bucket, key] : cuckoo_map)
    {
        bucket_to_position[bucket] = key_to_position[key];
        inv_cuckoo_map[key] = bucket;
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
    if (batchpir_params_.get_type() == UIUC) {
        size_t max_bucket_size = batchpir_params_.get_bucket_size();
        size_t num_hash_funcs = batchpir_params_.get_num_hash_funcs();
        size_t dim_size = batchpir_params_.get_first_dimension_size();
        auto max_slots = batchpir_params_.get_seal_parameters().poly_modulus_degree();
        auto num_buckets = ceil(batchpir_params_.get_batch_size() * batchpir_params_.get_cuckoo_factor());
        size_t per_client_capacity = max_slots / dim_size;
        size_t num_client = ceil(num_buckets / per_client_capacity);
        auto remaining_buckets = num_buckets;
        auto previous_idx = 0;
        seal::KeyGenerator *keygen;

        for (int i = 0; i < num_client; i++)
        {
            const size_t num_dbs = std::min(per_client_capacity, static_cast<size_t>(num_buckets - previous_idx));
            previous_idx += num_dbs;
            PirParams params(max_bucket_size, num_dbs, batchpir_params_.get_seal_parameters(), dim_size);
            if (i == 0)
            {
                Client client(params);
                client_list_.push_back(vector<Client>(num_hash_funcs, client));
                keygen = client.get_keygen();
            }
            else
            {
                Client client(params, keygen);
                client_list_.push_back(vector<Client>(num_hash_funcs, client));
            }
        }
    } else {
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
}

// return 1..w, 1..B
RawDB BatchPIRClient::decode_responses(vector<PIRResponseList> responses, vector<prefixblock> nonces, vector<block> encryption_masks)
{
    cout << serialized_comm_size_ << endl;
    serialized_comm_size_ += nonces.size() * sizeof(prefixblock);
    auto plaint_bit_count_ = batchpir_params_.get_seal_parameters().plain_modulus().bit_count();
    size_t w = batchpir_params_.get_num_hash_funcs();
    const auto num_columns_per_entry = batchpir_params_.get_num_slots_per_entry();
    const int size_of_coeff = plaint_bit_count_ - 1;
    size_t batch_size = batchpir_params_.get_batch_size();
    auto num_buckets = batchpir_params_.get_num_buckets();
    size_t num_subbucket = DatabaseConstants::PolyDegree / num_buckets;
    size_t bucket_size = batchpir_params_.get_bucket_size();
    size_t subbucket_size = ceil(bucket_size * 1.0 / num_subbucket);
    auto type = batchpir_params_.get_type();
    size_t dim_size = batchpir_params_.get_first_dimension_size();
    auto max_slots = batchpir_params_.get_seal_parameters().poly_modulus_degree();
    size_t per_server_capacity = max_slots / dim_size;
    size_t num_servers = ceil(num_buckets / per_server_capacity);

    vector<vector<block>> entries_list(num_buckets, vector<block>(w));
    for (int hash_idx = 0; hash_idx < w; hash_idx++)
    {
        auto& response = responses[hash_idx];
        measure_size(response);

        if (type == PIRANA) {
            vector<string> str_entries(num_buckets, "");
            for (int slot_idx = 0; slot_idx < num_columns_per_entry; slot_idx++)
            {
                size_t start = slot_idx * size_of_coeff;
                size_t end = std::min((slot_idx + 1) * size_of_coeff, (int)blocksize);
                vector<uint64_t> plain_entry(num_buckets);
                Plaintext pt;
                decryptor_->decrypt(response[slot_idx], pt);
                batch_encoder_->decode(pt, plain_entry);
                for (int bucket_idx = 0; bucket_idx < num_buckets; bucket_idx++) {
                    size_t subbucket_idx = bucket_to_position[bucket_idx][hash_idx] / subbucket_size;
                    str_entries[bucket_idx] += block(plain_entry[bucket_idx * num_subbucket + subbucket_idx]).to_string().substr(blocksize-(end - start));
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
        } else {

            const size_t num_slots_per_entry = batchpir_params_.get_num_slots_per_entry();
            const size_t num_slots_per_entry_rounded = utils::next_power_of_two(num_slots_per_entry);
            const size_t max_empty_slots = batchpir_params_.get_first_dimension_size();
            const size_t row_size = batchpir_params_.get_seal_parameters().poly_modulus_degree() / 2;
            const size_t gap = row_size / max_empty_slots;
            auto current_fill = gap * num_slots_per_entry_rounded;
            size_t num_buckets_merged = (row_size / current_fill);
            size_t num_chunk_ctx = ceil((num_slots_per_entry * 1.0) / max_empty_slots);
            RawResponses all_entries;

            if (ceil(num_slots_per_entry * 1.0 / max_empty_slots) > 1 || num_buckets_merged <= 1 || client_list_.size() == 1) {
                for (int i = 0; i < client_list_.size(); i++) {
                    auto start_idx = (i * num_chunk_ctx);
                    PIRResponseList subvector(response.begin() + start_idx, response.begin() + start_idx + num_chunk_ctx);
                    auto entries = client_list_[i][hash_idx].decode_responses(subvector);
                    all_entries.insert(all_entries.end(), entries.begin(), entries.end());
                }
            } else {
                exit(1);
                vector<vector<uint64_t>> entry_slot_lists;
                for (int i = 0; i < client_list_.size(); i++) {
                    entry_slot_lists.push_back(client_list_[i][hash_idx].get_entry_list());
                }
                auto list = client_list_[0][hash_idx].decode_merged_responses(response, num_buckets, entry_slot_lists);
                for (auto& e: list) {
                    all_entries.insert(all_entries.end(), e.begin(), e.end());
                }
            }

            assert (all_entries.size() == num_buckets);
            for (int bucket_idx = 0; bucket_idx < num_buckets; bucket_idx++) {
                if (cuckoo_map.count(bucket_idx)) {
                    entries_list[bucket_idx][hash_idx] = all_entries[bucket_idx] ^ encryption_masks[cuckoo_map[bucket_idx]];
                }
            }
            // Unmask
            #ifdef DEBUG 
            cout << fmt::format("query {}: Unmask {} with {} -> {}", hash_idx, all_entries[server->iB_of_interest].to_string(), encryption_masks[cuckoo_map.at(server->iB_of_interest)].to_string(), entries_list[server->iB_of_interest][hash_idx].to_string()) << endl;
            #endif
            
        }
    }

    // Nonce matching
    RawDB raw_responses(num_buckets);
    for (int batch_idx = 0; batch_idx < batch_size; batch_idx++) {
        bool flag = false;
        auto bucket_idx = inv_cuckoo_map[batch_idx];
        assert (cuckoo_map.count(bucket_idx));
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
    if (batchpir_params_.get_type() == UIUC) {
        return client_list_[0][0].get_public_keys();
    } else {
        return std::make_pair(gal_keys_, relin_keys_);
    }
}