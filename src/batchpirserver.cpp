#include "batchpirserver.h"
#include "utils.h"
#include <algorithm>
#include <cassert>
#include <cstdint>
#include <seal/ciphertext.h>
#include <seal/plaintext.h>
#include <array>
#include <stdexcept>
#include <string>
#include <utility>

using namespace utils;
using namespace DatabaseConstants;

BatchPIRServer::BatchPIRServer(BatchPirParams &batchpir_params)
{
    batchpir_params_ = &batchpir_params;
    is_client_keys_set_ = false;
    lowmc_encoded = false;
    is_db_populated = false;

    context_ = new SEALContext(batchpir_params_->get_seal_parameters());
    evaluator_ = new Evaluator(*context_);
    batch_encoder_ = new BatchEncoder(*context_);
    plaint_bit_count_ = batchpir_params_->get_seal_parameters().plain_modulus().bit_count();

}

void BatchPIRServer::initialize(vector<keyblock> keys, vector<prefixblock> prefixes) {
    check(is_db_populated, "Error: Database not populated.");
    initialize_masks();
    lowmc_prepare(keys, prefixes);
    lowmc_encode();
    lowmc_encrypt();
    prepare_pir_server();
}

void BatchPIRServer::populate_raw_db(std::function<rawdatablock(size_t)> generator)
{
    const auto db_entries = DBSize;

    // Resize the rawdb vector to the correct size
    rawdb_.resize(db_entries);

    // Populate the rawdb vector with entries
    for (size_t i = 0; i < db_entries; ++i)
    {
        rawdb_[i] = generator(i);
    }
    is_db_populated = true;
}

void BatchPIRServer::initialize_masks() {
    auto total_buckets = batchpir_params_->get_num_buckets();
    
    const auto w = NumHashFunctions;
    for (int hash_idx = 0; hash_idx < w; hash_idx++) {
        index_masks[hash_idx].resize(total_buckets);
        for (auto &r: index_masks[hash_idx])
            r = utils::random_bitset<InputLength>();
        
        entry_masks[hash_idx].resize(total_buckets);
        for (auto &r: entry_masks[hash_idx])
            r = utils::random_bitset<OutputLength>();
    }
}

void BatchPIRServer::lowmc_prepare(vector<keyblock> keys, vector<prefixblock> prefixes) {
    auto total_buckets = batchpir_params_->get_num_buckets();
    const auto db_entries = DBSize;
    const auto w = NumHashFunctions;
    auto bucket_size = batchpir_params_->get_bucket_size(); 
    bool parallel = batchpir_params_->is_parallel();

    for (size_t i = 0; i < w; i++) {
        ciphers.emplace_back(utils::LowMC(keys[i], prefixes[i]));
    }

    candidate_buckets_array.resize(db_entries);
    candidate_positions_array.resize(db_entries);

    std::vector<std::vector<string>> ciphertexts(db_entries, std::vector<string>(w));

    #pragma omp parallel for if(parallel) collapse(2)
    for (int hash_idx = 0; hash_idx < w; hash_idx++) {
        for (uint64_t i = 0; i < db_entries; i++) {
            block message = concatenate(ciphers[hash_idx].get_prefix(), rawinputblock(i));
            ciphertexts[i][hash_idx] = ciphers[hash_idx].encrypt(message).to_string();
        }
    }
    #pragma omp parallel for if(parallel)
    for (uint64_t i = 0; i < db_entries; i++) {
        utils::get_candidates_with_hash_values(total_buckets, bucket_size, ciphertexts[i], candidate_buckets_array[i], candidate_positions_array[i]);
    }

}

void BatchPIRServer::lowmc_encode() {
    auto total_buckets = batchpir_params_->get_num_buckets();
    const auto db_entries = DBSize;
    auto bucket_size = batchpir_params_->get_bucket_size();
    const auto w = NumHashFunctions;
    bool parallel = batchpir_params_->is_parallel();
    for (int hash_idx = 0; hash_idx < w; hash_idx++) {
        buckets_[hash_idx].resize(total_buckets, EncodedDB(bucket_size));
    }
    
    srand(time(nullptr));

    std::unordered_map<uint64_t, std::vector<size_t>> key_to_position;
    for (uint64_t i = 0; i < db_entries; i++) {
        key_to_position[i] = candidate_positions_array[i];
    }

    std::vector<std::vector<uint64_t>> insert_buffer(total_buckets);
    for (int bucket_idx = 0; bucket_idx < total_buckets; bucket_idx++)
        insert_buffer.reserve(bucket_size);
    for (uint64_t i = 0; i < db_entries; i++)
    {
        for (auto& b : candidate_buckets_array[i])
        {
            insert_buffer[b].push_back(i);
        }
    }

    position_to_key.resize(total_buckets);
    #pragma omp parallel for if(parallel)
    for (int bucket_idx = 0; bucket_idx < total_buckets; bucket_idx++) {
        for (auto& i: insert_buffer[bucket_idx]) {
            cuckoo_insert(i, 0, key_to_position, position_to_key[bucket_idx]);
        }
    }
}

void BatchPIRServer::lowmc_encrypt() {
    auto total_buckets = batchpir_params_->get_num_buckets();
    const auto db_entries = DBSize;
    auto bucket_size = batchpir_params_->get_bucket_size();
    const auto w = NumHashFunctions;
    bool parallel = batchpir_params_->is_parallel();
    
    #pragma omp parallel for if(parallel) collapse(2)
    for (int hash_idx = 0; hash_idx < w; hash_idx++) {
        for(size_t b = 0; b < total_buckets; b++) {
            for (auto const &[pos, idx] : position_to_key[b]) {
                buckets_[hash_idx][b][pos] = concatenate(rawinputblock(idx) ^ index_masks[hash_idx][b], rawdb_[idx] ^ entry_masks[hash_idx][b]);
            }
        }
    }

    lowmc_encoded = true;
}

void BatchPIRServer::prepare_pir_server()
{

    if (!lowmc_encoded)
    {
        throw std::logic_error("Error: lowmc encoding must be performed before preparing PIR server.");
    }

    auto num_buckets = batchpir_params_->get_num_buckets();
    size_t bucket_size = batchpir_params_->get_bucket_size();
    const auto max_slots = PolyDegree;
    size_t num_subbucket = max_slots / num_buckets;
    size_t subbucket_size = ceil(bucket_size * 1.0 / num_subbucket);
    auto type = batchpir_params_->get_type();
    size_t dim_size = batchpir_params_->get_first_dimension_size();
    size_t per_server_capacity = max_slots / dim_size;
    size_t num_servers = ceil(num_buckets * 1.0 / per_server_capacity);
    const auto num_columns_per_entry = batchpir_params_->get_num_slots_per_entry();
    const int size_of_coeff = plaint_bit_count_ - 1;
    auto pid = context_->first_parms_id();
    const auto w = NumHashFunctions;
    bool parallel = batchpir_params_->is_parallel();

    for (int hash_idx = 0; hash_idx < w; hash_idx++) {
        if (type == PIRANA) {
            const size_t entry_size = utils::datablock_size;
            encoded_columns[hash_idx].resize(subbucket_size, vector<Plaintext>(num_columns_per_entry));
            
            #pragma omp parallel for if(parallel)
            for (auto column = 0; column < subbucket_size; column++) {
                for (size_t slot_idx = 0; slot_idx < num_columns_per_entry; slot_idx++) {
                    size_t start = slot_idx * size_of_coeff;
                    size_t end = std::min((slot_idx + 1) * size_of_coeff, entry_size);
                    vector<uint64_t> plain_col;
                    plain_col.reserve(num_buckets * num_subbucket);
                    for (auto bucket_idx = 0; bucket_idx < num_buckets; bucket_idx++) {
                        for (size_t subbucket_idx = 0; subbucket_idx < num_subbucket; subbucket_idx++) {
                            size_t selected_column = subbucket_idx*subbucket_size + column;
                            if (selected_column > buckets_[hash_idx][bucket_idx].size()) {
                                plain_col.push_back(0);
                            } else {
                                string sub = buckets_[hash_idx][bucket_idx][selected_column].to_string().substr(start, end - start);
                                uint64_t item = std::stoull(sub, 0, 2);
                                plain_col.push_back(item);
                            }
                        }
                    }
                    batch_encoder_->encode(plain_col, encoded_columns[hash_idx][column][slot_idx]);
                }
                
            }

            #pragma omp parallel for collapse(2) if(parallel)
            for (int column = 0; column < subbucket_size; column++) {
                for (size_t slot_idx = 0; slot_idx < num_columns_per_entry; slot_idx++) {
                    evaluator_->transform_to_ntt_inplace(encoded_columns[hash_idx][column][slot_idx], pid);
                }
            }
        } else {
            auto previous_idx = 0;
            for (int i = 0; i < num_servers; i++)
            {
                const size_t offset = std::min(per_server_capacity, num_buckets - previous_idx);
                vector<EncodedDB> sub_buckets(buckets_[hash_idx].begin() + previous_idx, buckets_[hash_idx].begin() + previous_idx + offset);
                previous_idx += offset;

                PirParams params(bucket_size, offset, batchpir_params_->get_seal_parameters(), batchpir_params_->get_default_value(), dim_size);
                params.print_values();
                Server server(params, sub_buckets);

                server_list_[hash_idx].push_back(server);
            }
        }
    }
}

void BatchPIRServer::set_client_keys(uint32_t client_id, std::pair<vector<seal_byte>, vector<seal_byte>> keys)
{
    const auto w = NumHashFunctions;
    auto type = batchpir_params_->get_type();

    if (type == PIRANA) {
        auto [glk_buffer, rlk_buffer] = keys;
        seal::RelinKeys rlk;
        rlk.load(*context_, rlk_buffer.data(), rlk_buffer.size());
        client_keys_[client_id] = rlk;
    } else {
        for (int hash_idx = 0; hash_idx < w; hash_idx++) {
            for (int i = 0; i < server_list_[hash_idx].size(); i++)
            {
                server_list_[hash_idx][i].set_client_keys(client_id, keys);
            }
        }
    }
    
    is_client_keys_set_ = true;
}

vector<PIRResponseList> BatchPIRServer::generate_response(uint32_t client_id, vector<vector<PIRQuery>> queries)
{

    if (!is_client_keys_set_)
    {
        throw std::runtime_error("Error: Client keys not set");
    }
    
    auto num_buckets = batchpir_params_->get_num_buckets();
    size_t bucket_size = batchpir_params_->get_bucket_size();
    size_t num_subbucket = PolyDegree / num_buckets;
    size_t subbucket_size = ceil(bucket_size * 1.0 / num_subbucket);
    const auto [m, k] = batchpir_params_->get_PIRANA_params();
    const auto w = NumHashFunctions;
    const auto num_columns_per_entry = batchpir_params_->get_num_slots_per_entry();
    auto type = batchpir_params_->get_type();
    size_t dim_size = batchpir_params_->get_first_dimension_size();
    const auto max_slots = PolyDegree;
    size_t per_server_capacity = max_slots / dim_size;
    size_t num_servers = ceil(num_buckets * 1.0 / per_server_capacity);
    bool parallel = batchpir_params_->is_parallel();

    vector<PIRResponseList> response(w);

    for (int hash_idx = 0; hash_idx < w; hash_idx++) {
        if (type == PIRANA) {
            masked_value.clear();
            masked_value.resize(num_columns_per_entry, PIRResponseList(subbucket_size));
            response[hash_idx].resize(num_columns_per_entry);

            vector<vector<Ciphertext>> c_to_mul(subbucket_size);
            for (int column=0; column < subbucket_size; column++) {
                auto code = utils::get_perfect_constant_weight_codeword(column, m, k);
                for (int code_idx = 0; code_idx < m; code_idx++) {
                    if (code[code_idx] == 1ULL) {
                        c_to_mul[column].push_back(queries[hash_idx][0][code_idx]);
                    }
                }
            }

            #pragma omp parallel for if(parallel)
            for (int column=0; column < subbucket_size; column++) {
                Ciphertext mask;
                
                evaluator_->multiply_many(c_to_mul[column], client_keys_[client_id], mask);
                evaluator_->transform_to_ntt_inplace(mask);
                // Get column
                for (int slot_idx = 0; slot_idx < num_columns_per_entry; slot_idx++) {
                    evaluator_->multiply_plain(mask, encoded_columns[hash_idx][column][slot_idx], masked_value[slot_idx][column]);
                }
            }
            for (int slot_idx = 0; slot_idx < num_columns_per_entry; slot_idx++) {
                evaluator_->add_many(masked_value[slot_idx], response[hash_idx][slot_idx]);
                evaluator_->transform_from_ntt_inplace(response[hash_idx][slot_idx]);
                evaluator_->mod_switch_to_next_inplace(response[hash_idx][slot_idx]); // reduce ciphertext space
            }
        } else {
            int previous_idx = 0;
            vector<PIRResponseList> resp_list;
            for (int server_idx = 0; server_idx < server_list_[hash_idx].size(); server_idx++)
            {
                resp_list.push_back(server_list_[hash_idx][server_idx].generate_response(client_id, queries[hash_idx][server_idx]));
            }
            response[hash_idx] = server_list_[hash_idx][0].merge_responses_chunks_buckets(resp_list, client_id);
        }
    }
    
    return response;
}

bool BatchPIRServer::check_decoded_entries(vector<EncodedDB> entries_list, vector<rawinputblock>& queries, std::unordered_map<uint64_t, uint64_t> cuckoo_map)
{
    const auto w = NumHashFunctions;
    for (auto const &[bucket, original_index] : cuckoo_map) {
        if (queries[original_index].to_ullong() >= DBSize)
            continue;
        bool flag = false;
        for (int hash_idx = 0; hash_idx < w; hash_idx++) {
            const auto pos = candidate_positions_array[queries[original_index].to_ullong()][hash_idx];
            auto [index, entry] = utils::split<InputLength>(entries_list[bucket][hash_idx]);
            utils::check(entries_list[bucket][hash_idx] == buckets_[hash_idx][bucket][pos], fmt::format("Decode problem. {} != {}", entries_list[bucket][hash_idx].to_string(), buckets_[hash_idx][bucket][pos].to_string()));
            auto idx = index ^ index_masks[hash_idx][bucket];
            auto data = entry ^ entry_masks[hash_idx][bucket];
            if (idx == queries[original_index] && data == rawdb_[queries[original_index].to_ullong()]) {
                flag = true;
            }
        }
        utils::check(flag, "Multiple match. ");
    }

    return true;
}
