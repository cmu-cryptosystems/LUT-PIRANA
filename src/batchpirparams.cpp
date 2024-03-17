#include "batchpirparams.h"
#include <iomanip>
#include "LowMC.h"
#include "utils.h"

BatchPirParams::BatchPirParams(int batch_size, size_t num_entries, size_t entry_size, bool parallel, BatchPirType type, uint64_t pirana_k)
    : num_hash_funcs_(DatabaseConstants::NumHashFunctions),
      batch_size_(batch_size),
      cuckoo_factor_(DatabaseConstants::CuckooFactor),
      cuckoo_factor_bucket_(DatabaseConstants::CuckooFactorBucket),
      num_entries_(num_entries),
      entry_size_(utils::datablock_size),
      max_attempts_(DatabaseConstants::MaxAttempts),
      parallel(parallel),
      type_(type),  
      PIRANA_k(pirana_k) {

    std::string selection = std::to_string(batch_size) + "," + std::to_string(num_entries) + "," + std::to_string(entry_size);
    seal_params_ = utils::create_encryption_parameters(selection);
    auto max_slots = seal_params_.poly_modulus_degree();
    auto num_buckets = get_num_buckets();
    size_t bucket_size = get_bucket_size();
    if (type_ == UIUC) {
        set_first_dimension_size();
        size_t dim_size = get_first_dimension_size();
        size_t per_server_capacity = max_slots / dim_size;
        size_t num_servers = ceil(num_buckets * 1.0 / per_server_capacity);
        size_t num_chunk_ctx = ceil((get_num_slots_per_entry() * 1.0) / dim_size);

        query_size = {size_t(num_hash_funcs_), num_servers, 3};
        response_size = {size_t(num_hash_funcs_),  num_servers * num_chunk_ctx};
    } else {
        size_t num_subbucket = max_slots / num_buckets;
        size_t subbucket_size = ceil(bucket_size * 1.0 / num_subbucket);
        
        for (PIRANA_m = 2; utils::choose(PIRANA_m, PIRANA_k) < subbucket_size; PIRANA_m++); 

        query_size = {size_t(num_hash_funcs_), 1, PIRANA_m};
        response_size = {size_t(num_hash_funcs_),  get_num_slots_per_entry()};
    }

    default_value_ = type == PIRANA ? 1 : std::numeric_limits<uint64_t>().max();

}

int BatchPirParams::get_num_hash_funcs() {
    return num_hash_funcs_;
}

EncryptionParameters BatchPirParams::get_seal_parameters() const
{
    return seal_params_;
}

// entry_size_ = 128 bits = 16 Bytes
uint32_t BatchPirParams::get_num_slots_per_entry() {
    return ceil((entry_size_ * 1.0) / (seal_params_.plain_modulus().bit_count()-1));
}

int BatchPirParams::get_batch_size() {
    return batch_size_;
}

double BatchPirParams::get_cuckoo_factor() {
    return cuckoo_factor_;
}

double BatchPirParams::get_cuckoo_factor_bucket() {
    return cuckoo_factor_bucket_;
}

size_t BatchPirParams::get_num_entries() {
    return num_entries_;
}

size_t BatchPirParams::get_num_buckets() {
    return ceil(cuckoo_factor_ * batch_size_);
}

size_t BatchPirParams::get_bucket_size() {
    return ceil(cuckoo_factor_bucket_ * num_hash_funcs_ * num_entries_ / get_num_buckets());
}

size_t BatchPirParams::get_entry_size() {
    return entry_size_;
}

size_t BatchPirParams::get_max_attempts() {
    return max_attempts_;
}

size_t BatchPirParams::get_first_dimension_size() {
    return dim_size_;
}

uint64_t BatchPirParams::get_default_value(){
    return default_value_;
}

void BatchPirParams::set_first_dimension_size(){
    size_t cube_root = std::ceil(std::cbrt(get_bucket_size()));
    dim_size_ = utils::next_power_of_two(cube_root);
    auto dim_size = dim_size_;
    auto prev_dim_size = dim_size;
    auto batch_size = ceil((batch_size_*cuckoo_factor_)*1.0/2);
    while(batch_size * dim_size <= seal_params_.poly_modulus_degree()/2){
        prev_dim_size = dim_size;
        dim_size = utils::next_power_of_two(dim_size + 1);
        
    }
    dim_size_ = prev_dim_size;
}

void BatchPirParams::print_params() const {
std::cout << "+---------------------------------------------------+" << std::endl;
std::cout << "|                  Batch Parameters                 |" << std::endl;
std::cout << "+---------------------------------------------------+" << std::endl;
std::cout << std::left << std::setw(20) << "| num_hash_funcs_: " << num_hash_funcs_ << std::endl;
std::cout << std::left << std::setw(20) << "| batch_size_: " << batch_size_ << std::endl;
std::cout << std::left << std::setw(20) << "| cuckoo_factor_: " << cuckoo_factor_ << std::endl;
std::cout << std::left << std::setw(20) << "| num_entries_: " << num_entries_ << std::endl;
std::cout << std::left << std::setw(20) << "| max_attempts_: " << max_attempts_ << std::endl;
std::cout << "+---------------------------------------------------+" << std::endl;
}