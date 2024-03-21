#include "batchpirserver.h"
#include "utils.h"
#include <algorithm>
#include <cstdint>
#include <seal/ciphertext.h>
#include <seal/plaintext.h>
#include <array>
#include <stdexcept>
#include <string>
#include <utility>

using namespace utils;

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
    polynomial_degree_ = batchpir_params_->get_seal_parameters().poly_modulus_degree();
    row_size_ = polynomial_degree_ / 2;

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
    auto db_entries = batchpir_params_->get_num_entries();

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
    
    size_t w = batchpir_params_->get_num_hash_funcs();
    for (int hash_idx = 0; hash_idx < w; hash_idx++) {
        index_masks[hash_idx].resize(total_buckets);
        for (auto &r: index_masks[hash_idx])
            r = utils::random_bitset<DatabaseConstants::InputLength>();
        
        entry_masks[hash_idx].resize(total_buckets);
        for (auto &r: entry_masks[hash_idx])
            r = utils::random_bitset<DatabaseConstants::OutputLength>();
    }
}

inline void get_candidate_lowmc(size_t data, size_t total_buckets, size_t bucket_size, std::vector<size_t>& candidate_buckets, std::vector<size_t>& candidate_position, std::vector<utils::LowMC>& ciphers) {
    rawinputblock d(data);
    std::vector<string> ciphertexts;
    for (auto& cipher: ciphers) {
        auto message = concatenate(cipher.get_prefix(), d);
        auto ciphertext = cipher.encrypt(message).to_string();
        ciphertexts.emplace_back(ciphertext);
    }
    std::tie(candidate_buckets, candidate_position) = utils::get_candidates_with_hash_values(total_buckets, bucket_size, ciphertexts);
}

void BatchPIRServer::lowmc_prepare(vector<keyblock> keys, vector<prefixblock> prefixes) {
    auto total_buckets = batchpir_params_->get_num_buckets();
    auto num_candidates = batchpir_params_->get_num_hash_funcs();
    auto db_entries = batchpir_params_->get_num_entries();
    auto bucket_size = ceil(batchpir_params_->get_cuckoo_factor_bucket() * num_candidates * db_entries / total_buckets); 
    bool parallel = batchpir_params_->is_parallel();

    for (size_t i = 0; i < batchpir_params_->get_num_hash_funcs(); i++) {
        ciphers.emplace_back(utils::LowMC(keys[i], prefixes[i]));
    }
    check(num_candidates == ciphers.size());

    candidate_buckets_array.resize(db_entries);
    candidate_positions_array.resize(db_entries);

    #pragma omp parallel for if(parallel)
    for (uint64_t i = 0; i < db_entries; i++) {
        get_candidate_lowmc(i, total_buckets, bucket_size, candidate_buckets_array[i], candidate_positions_array[i], ciphers);
    }

}

void BatchPIRServer::lowmc_encode() {
    auto total_buckets = batchpir_params_->get_num_buckets();
    auto db_entries = batchpir_params_->get_num_entries();
    auto num_candidates = batchpir_params_->get_num_hash_funcs();
    auto bucket_size = batchpir_params_->get_bucket_size();
    size_t w = batchpir_params_->get_num_hash_funcs();
    for (int hash_idx = 0; hash_idx < w; hash_idx++) {
        buckets_[hash_idx].resize(total_buckets);
        for(auto &b : buckets_[hash_idx])
            b.resize(bucket_size);
    }
    
    // srand(time(nullptr));

    std::vector<std::unordered_map<uint64_t, std::vector<size_t>>> key_to_position(total_buckets);
    position_to_key.resize(total_buckets);
    for (uint64_t i = 0; i < db_entries; i++)
    {
        for (auto b : candidate_buckets_array[i])
        {
            // cuckoo insert
            key_to_position[b][i] = candidate_positions_array[i];
            cuckoo_insert(i, 0, key_to_position[b], position_to_key[b]);
        }
    }
}

void BatchPIRServer::lowmc_encrypt() {
    auto total_buckets = batchpir_params_->get_num_buckets();
    auto db_entries = batchpir_params_->get_num_entries();
    auto bucket_size = batchpir_params_->get_bucket_size();
    size_t w = batchpir_params_->get_num_hash_funcs();
    bool parallel = batchpir_params_->is_parallel();
    
    #pragma omp parallel for if(parallel)
    for(size_t b = 0; b < total_buckets; b++) {
        for (auto const &[pos, idx] : position_to_key[b]) {
            for (int hash_idx = 0; hash_idx < w; hash_idx++) {
                buckets_[hash_idx][b][pos] = concatenate(rawinputblock(idx) ^ index_masks[hash_idx][b], rawdb_[idx] ^ entry_masks[hash_idx][b]);
            }
        }
    }

    lowmc_encoded = true;
}

// void BatchPIRServer::print_stats() const
// {
//     std::cout << "BatchPIRServer: Bucket Statistics:\n";
//     std::cout << "===================\n";
//     std::cout << "BatchPIRServer: Number of Buckets: " << buckets_.size() << "\n";

//     // size_t max_bucket_size = get_bucket_size();
//     // size_t min_bucket_size = get_min_bucket_size();
//     // size_t avg_bucket_size = get_avg_bucket_size();

//     // std::cout << "Max Bucket Size: " << max_bucket_size << "\n";
//     // std::cout << "Min Bucket Size: " << min_bucket_size << "\n";
//     // std::cout << "Avg Bucket Size: " << avg_bucket_size << "\n";
// }

// size_t BatchPIRServer::get_first_dimension_size(size_t num_entries)
// {
//     size_t cube_root = std::ceil(std::cbrt(num_entries));
//     return utils::next_power_of_two(cube_root);
// }

void BatchPIRServer::prepare_pir_server()
{

    if (!lowmc_encoded)
    {
        throw std::logic_error("Error: lowmc encoding must be performed before preparing PIR server.");
    }

    auto num_buckets = batchpir_params_->get_num_buckets();
    size_t bucket_size = batchpir_params_->get_bucket_size();
    size_t num_subbucket = polynomial_degree_ / num_buckets;
    size_t subbucket_size = ceil(bucket_size * 1.0 / num_subbucket);
    auto type = batchpir_params_->get_type();
    size_t dim_size = batchpir_params_->get_first_dimension_size();
    auto max_slots = batchpir_params_->get_seal_parameters().poly_modulus_degree();
    size_t per_server_capacity = max_slots / dim_size;
    size_t num_servers = ceil(num_buckets * 1.0 / per_server_capacity);
    const auto num_columns_per_entry = batchpir_params_->get_num_slots_per_entry();
    const int size_of_coeff = plaint_bit_count_ - 1;
    auto pid = context_->first_parms_id();
    size_t w = batchpir_params_->get_num_hash_funcs();
    bool parallel = batchpir_params_->is_parallel();

    for (int hash_idx = 0; hash_idx < w; hash_idx++) {
        if (type == PIRANA) {
            size_t entry_size = batchpir_params_->get_entry_size();
            encoded_columns[hash_idx].resize(subbucket_size, vector<Plaintext>(num_columns_per_entry));
            
            #pragma omp parallel for if(parallel)
            for (auto column = 0; column < subbucket_size; column++) {
                vector<vector<uint64_t>> plain_col(num_columns_per_entry);
                for (size_t slot_idx = 0; slot_idx < num_columns_per_entry; slot_idx++) {
                    size_t start = slot_idx * size_of_coeff;
                    size_t end = std::min((slot_idx + 1) * size_of_coeff, entry_size);
                    for (auto bucket_idx = 0; bucket_idx < num_buckets; bucket_idx++) {
                        for (size_t subbucket_idx = 0; subbucket_idx < num_subbucket; subbucket_idx++) {
                            size_t selected_column = subbucket_idx*subbucket_size + column;
                            if (selected_column > buckets_[hash_idx][bucket_idx].size()) {
                                plain_col[slot_idx].push_back(0);
                            } else {
                                string sub = buckets_[hash_idx][bucket_idx][selected_column].to_string().substr(start, end - start);
                                uint64_t item = std::stoull(sub, 0, 2);
                                plain_col[slot_idx].push_back(item);
                            }
                        }
                    }
                    batch_encoder_->encode(plain_col[slot_idx], encoded_columns[hash_idx][column][slot_idx]);
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
    size_t w = batchpir_params_->get_num_hash_funcs();
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
    size_t num_subbucket = polynomial_degree_ / num_buckets;
    size_t subbucket_size = ceil(bucket_size * 1.0 / num_subbucket);
    const auto [m, k] = batchpir_params_->get_PIRANA_params();
    size_t w = batchpir_params_->get_num_hash_funcs();
    const auto num_columns_per_entry = batchpir_params_->get_num_slots_per_entry();
    auto type = batchpir_params_->get_type();
    size_t dim_size = batchpir_params_->get_first_dimension_size();
    auto max_slots = batchpir_params_->get_seal_parameters().poly_modulus_degree();
    size_t per_server_capacity = max_slots / dim_size;
    size_t num_servers = ceil(num_buckets / per_server_capacity);
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
    size_t w = batchpir_params_->get_num_hash_funcs();
    for (auto const &[bucket, original_index] : cuckoo_map) {
        if (queries[original_index].to_ullong() >= batchpir_params_->get_num_entries())
            continue;
        bool flag = false;
        for (int hash_idx = 0; hash_idx < w; hash_idx++) {
            const auto pos = candidate_positions_array[queries[original_index].to_ullong()][hash_idx];
            auto [index, entry] = utils::split<DatabaseConstants::InputLength>(entries_list[bucket][hash_idx]);
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
