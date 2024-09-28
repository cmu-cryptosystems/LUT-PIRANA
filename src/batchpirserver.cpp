#include "batchpirserver.h"
#include "utils.h"
#include <algorithm>
#include <cassert>
#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Crypto/PRNG.h>
#include <cstdint>
#include <seal/ciphertext.h>
#include <seal/plaintext.h>
#include <array>
#include <stdexcept>
#include <string>
#include <utility>

using namespace utils;
using namespace DatabaseConstants;

BatchPIRServer::BatchPIRServer(BatchPirParams &batchpir_params, osuCrypto::PRNG &prng)
{
    batchpir_params_ = &batchpir_params;
    is_client_keys_set_ = false;
    hash_encoded = false;
    is_db_populated = false;

    context_ = new SEALContext(batchpir_params_->get_seal_parameters());
    evaluator_ = new Evaluator(*context_);
    batch_encoder_ = new BatchEncoder(*context_);
    plaint_bit_count_ = batchpir_params_->get_seal_parameters().plain_modulus().bit_count();

    prng_ = &prng;

}

void BatchPIRServer::initialize() {
    initialize_masks();
    hash_encode();
    hash_encrypt();
    prepare_pir_server();
}

void BatchPIRServer::populate_raw_db(std::map<size_t, size_t>& lut)
{
    int num_threads = batchpir_params_->get_num_threads();
    input_keys.reserve(lut.size());

    // Resize the rawdb vector to the correct size
    rawdb_.reserve(lut.size());

    // Populate the rawdb vector with entries
    for (auto& item : lut)
    {
        input_keys.push_back(item.first);
        rawdb_.push_back(item.second);
    }
    is_db_populated = true;
}

void BatchPIRServer::populate_raw_db(std::function<rawdatablock(size_t)> generator)
{
    size_t db_entries = batchpir_params_->get_db_size();
    int num_threads = batchpir_params_->get_num_threads();

    // Resize the rawdb vector to the correct size
    input_keys.resize(db_entries);
	std::iota(input_keys.begin(), input_keys.end(), 0);
    rawdb_.resize(db_entries);

    // Populate the rawdb vector with entries
    #pragma omp parallel for num_threads(num_threads)
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
            r = utils::random_bitset<InputLength>(prng_);
        
        entry_masks[hash_idx].resize(total_buckets);
        for (auto &r: entry_masks[hash_idx])
            r = utils::random_bitset<OutputLength>(prng_);
    }
}

void BatchPIRServer::lowmc_prepare(keyblock oprf_key, prefixblock oprf_prefix) {
    check(is_db_populated, "Error: Database not populated.");
    auto total_buckets = batchpir_params_->get_num_buckets();
    size_t db_entries = batchpir_params_->get_db_size();
    const auto w = NumHashFunctions;
    auto bucket_size = batchpir_params_->get_bucket_size(); 
    bool parallel = batchpir_params_->is_parallel();
    int num_threads = batchpir_params_->get_num_threads();

    lowmc_oprf = new utils::LowMC(oprf_key, oprf_prefix);

    candidate_buckets_array.resize(db_entries);
    candidate_positions_array.resize(db_entries);

    string str_prefixes = oprf_prefix.to_string();

    #pragma omp parallel for if(parallel) num_threads(num_threads)
    for (uint64_t i = 0; i < db_entries; i++) {
        string oprf_output = lowmc_oprf->encrypt(
            block(str_prefixes + rawinputblock(input_keys[i]).to_string())
        ).to_string();
        candidate_buckets_array[i] = get_candidate_buckets(oprf_output, w, total_buckets);
        candidate_positions_array[i] = get_candidate_positions(oprf_output, w, bucket_size);
    }
}

void BatchPIRServer::aes_prepare(oc::block oprf_key, std::bitset<128-DatabaseConstants::InputLength> oprf_prefix) {
    check(is_db_populated, "Error: Database not populated.");
    auto total_buckets = batchpir_params_->get_num_buckets();
    size_t db_entries = batchpir_params_->get_db_size();
    const auto w = NumHashFunctions;
    auto bucket_size = batchpir_params_->get_bucket_size(); 
    bool parallel = batchpir_params_->is_parallel();
    int num_threads = batchpir_params_->get_num_threads();

    aes_oprf = new oc::AES(oprf_key);

    candidate_buckets_array.resize(db_entries);
    candidate_positions_array.resize(db_entries);

    uint64_t high_prefix;
    string low_prefix;
    auto str = oprf_prefix.to_string();
    high_prefix = block(str.substr(0, 64)).to_ullong();
    low_prefix = str.substr(64);

    #pragma omp parallel for if(parallel) num_threads(num_threads)
    for (uint64_t i = 0; i < db_entries; i++) {
        alignas(16) uint64_t data[2];
        data[0] = block(low_prefix + rawinputblock(input_keys[i]).to_string()).to_ullong();
        data[1] = high_prefix;
        auto c = aes_oprf->ecbEncBlock(
            oc::block(_mm_load_si128((__m128i*)data))
        ).get<uint64_t>();
        auto oprf_output = std::bitset<64>(c[1]).to_string() + std::bitset<64>(c[0]).to_string();
        candidate_buckets_array[i] = get_candidate_buckets(oprf_output, w, total_buckets);
        candidate_positions_array[i] = get_candidate_positions(oprf_output, w, bucket_size);
    }
}

void BatchPIRServer::hash_encode() {
    auto total_buckets = batchpir_params_->get_num_buckets();
    size_t db_entries = batchpir_params_->get_db_size();
    auto bucket_size = batchpir_params_->get_bucket_size();
    const auto w = NumHashFunctions;
    bool parallel = batchpir_params_->is_parallel();
    int num_threads = batchpir_params_->get_num_threads();

    srand(time(nullptr)); // Used for local cuckoo hashing, no need to be cryptographically secure. 

    std::vector<std::vector<uint64_t>> insert_buffer(total_buckets);
    for (int bucket_idx = 0; bucket_idx < total_buckets; bucket_idx++)
        insert_buffer[bucket_idx].reserve(bucket_size);
    for (uint64_t i = 0; i < db_entries; i++)
    {
        for (auto& b : candidate_buckets_array[i])
        {
            insert_buffer[b].push_back(i);
        }
    }

    position_to_key.resize(total_buckets);
    #pragma omp parallel for if(parallel) num_threads(num_threads)
    for (int bucket_idx = 0; bucket_idx < total_buckets; bucket_idx++) {
        for (auto& i: insert_buffer[bucket_idx]) {
            cuckoo_insert(i, 0, candidate_positions_array, position_to_key[bucket_idx]);
        }
        // for (auto& item: position_to_key[bucket_idx]) {
        //     item.second = input_keys[item.second];
        // }
    }
}

void BatchPIRServer::hash_encrypt() {
    auto total_buckets = batchpir_params_->get_num_buckets();
    auto bucket_size = batchpir_params_->get_bucket_size();
    const auto w = NumHashFunctions;
    bool parallel = batchpir_params_->is_parallel();
    int num_threads = batchpir_params_->get_num_threads();
    auto type = batchpir_params_->get_type();
    
    if (type == UIUC) {
        for (int hash_idx = 0; hash_idx < w; hash_idx++) 
            buckets_[hash_idx].resize(total_buckets, EncodedDB(bucket_size));
        #pragma omp parallel for if(parallel) collapse(2) num_threads(num_threads)
        for (int hash_idx = 0; hash_idx < w; hash_idx++) {
            for(size_t b = 0; b < total_buckets; b++) {
                for (auto const &[pos, idx] : position_to_key[b]) {
                    buckets_[hash_idx][b][pos] = concatenate(rawinputblock(idx) ^ index_masks[hash_idx][b], rawdb_[idx] ^ entry_masks[hash_idx][b]);
                }
            }
        }
    }

    hash_encoded = true;
}

void BatchPIRServer::prepare_pir_server()
{

    if (!hash_encoded)
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
            continue;
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
    size_t num_tasks_per_group = ceil(subbucket_size * 1.0 / NumTaskGroups);
    const auto m = batchpir_params_->get_PIRANA_m();
    const auto w = NumHashFunctions;
    const auto num_columns_per_entry = batchpir_params_->get_num_slots_per_entry();
    auto type = batchpir_params_->get_type();
    size_t dim_size = batchpir_params_->get_first_dimension_size();
    const auto max_slots = PolyDegree;
    size_t per_server_capacity = max_slots / dim_size;
    size_t num_servers = ceil(num_buckets * 1.0 / per_server_capacity);
    bool parallel = batchpir_params_->is_parallel();
    int num_threads = batchpir_params_->get_num_threads();
    const int size_of_coeff = plaint_bit_count_ - 1;
    auto pid = context_->first_parms_id();

    vector<PIRResponseList> response(w, PIRResponseList(num_columns_per_entry));

    for (int hash_idx = 0; hash_idx < w; hash_idx++) {
        if (type == PIRANA) {
            vector<PIRResponseList> masked_value(num_columns_per_entry, PIRResponseList(NumTaskGroups));

            #pragma omp parallel for if(parallel) num_threads(num_threads)
            for (int thread_idx = 0; thread_idx < NumTaskGroups; thread_idx++) {
                size_t col_start = thread_idx * num_tasks_per_group;
                size_t col_end = std::min((thread_idx + 1) * num_tasks_per_group, subbucket_size);

                for (int sub_column=0; sub_column < col_end - col_start; sub_column++) {
                    int column = col_start + sub_column;
                    utils::check(column < subbucket_size, fmt::format("Column {}={}+{} out of range", column, col_start, sub_column)); 
                    Ciphertext mask;

                    vector<long> query_indices = get_perfect_constant_weight_codeword_position(column, m, pirana_k);
                    vector<Ciphertext> selected_queries(pirana_k);
                    std::transform(query_indices.begin(), query_indices.end(), selected_queries.begin(), [&](long idx) {
                        return queries[hash_idx][0][idx];
                    });
                    
                    evaluator_->multiply_many(selected_queries, client_keys_[client_id], mask);
                    evaluator_->transform_to_ntt_inplace(mask);
                    
                    vector<vector<uint64_t>> plain_col(num_columns_per_entry);
                    for (size_t slot_idx = 0; slot_idx < num_columns_per_entry; slot_idx++) 
                        plain_col[slot_idx].reserve(num_buckets * num_subbucket);

                    for (size_t bucket_idx = 0; bucket_idx < num_buckets; bucket_idx++) {
                        for (size_t subbucket_idx = 0; subbucket_idx < num_subbucket; subbucket_idx++) {
                            size_t selected_column = subbucket_idx*subbucket_size + column;
                            if (position_to_key[bucket_idx].count(selected_column)) {
                                // Concatenation of index and data
                                auto plain_value = 
                                    (rawinputblock(input_keys[position_to_key[bucket_idx][selected_column]]) ^ index_masks[hash_idx][bucket_idx]).to_string() + 
                                    (rawdb_[position_to_key[bucket_idx][selected_column]] ^ entry_masks[hash_idx][bucket_idx]).to_string();
                                for (size_t slot_idx = 0; slot_idx < num_columns_per_entry; slot_idx++) {
                                    size_t start = slot_idx * size_of_coeff;
                                    size_t end = std::min((slot_idx + 1) * size_of_coeff, (size_t)datablock_size);
                                    string sub = plain_value.substr(start, end - start);
                                    uint64_t item = std::stoull(sub, 0, 2);
                                    plain_col[slot_idx].push_back(item);
                                }
                            } else {
                                for (size_t slot_idx = 0; slot_idx < num_columns_per_entry; slot_idx++) {
                                    plain_col[slot_idx].push_back(0);
                                }
                            }
                        }
                    }
                    for (size_t slot_idx = 0; slot_idx < num_columns_per_entry; slot_idx++) {
                        Plaintext pt;
                        Ciphertext masked_value_thread;
                        batch_encoder_->encode(plain_col[slot_idx], pt);
                        evaluator_->transform_to_ntt_inplace(pt, pid);
                        evaluator_->multiply_plain(mask, pt, masked_value_thread);

                        if (sub_column == 0) {
                            masked_value[slot_idx][thread_idx] = masked_value_thread;
                        } else {
                            evaluator_->add_inplace(masked_value[slot_idx][thread_idx], masked_value_thread);
                        }
                    }
                }
            }
            
            #pragma omp parallel for if(parallel) num_threads(num_threads)
            for (int slot_idx = 0; slot_idx < num_columns_per_entry; slot_idx++) {
                evaluator_->add_many(masked_value[slot_idx], response[hash_idx][slot_idx]);
                evaluator_->transform_from_ntt_inplace(response[hash_idx][slot_idx]);
                NoiseFloodInplace(response[hash_idx][slot_idx], *context_, batchpir_params_->noise_bits);
                evaluator_->mod_switch_to_inplace(response[hash_idx][slot_idx], context_->last_parms_id()); // reduce ciphertext space
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
    size_t db_entries = batchpir_params_->get_db_size();
    const auto w = NumHashFunctions;
    for (auto const &[bucket, original_index] : cuckoo_map) {
        if (queries[original_index].to_ullong() >= db_entries)
            continue;
        bool flag = false;
        for (int hash_idx = 0; hash_idx < w; hash_idx++) {
            const auto pos = candidate_positions_array[queries[original_index].to_ullong()][hash_idx];
            auto [index, entry] = utils::split<InputLength>(entries_list[bucket][hash_idx]);
            auto gt_entry = 
                position_to_key[bucket].count(pos) ? concatenate(rawinputblock(input_keys[position_to_key[bucket][pos]]) ^ index_masks[hash_idx][bucket], rawdb_[position_to_key[bucket][pos]] ^ entry_masks[hash_idx][bucket]) : 0;
            utils::check(entries_list[bucket][hash_idx] == gt_entry, fmt::format("Decode problem. {} != {}", entries_list[bucket][hash_idx].to_string(), gt_entry.to_string()));
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
