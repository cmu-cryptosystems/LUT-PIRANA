#include "batchpirparams.h"
#include <iomanip>
#include "LowMC.h"
#include "utils.h"

using namespace DatabaseConstants;

BatchPirParams::BatchPirParams(int batch_size, bool parallel, BatchPirType type, uint64_t pirana_k)
    : batch_size_(batch_size),
      parallel(parallel),
      type_(type),  
      PIRANA_k(pirana_k) {

    std::string selection = std::to_string(batch_size) + "," + std::to_string(DBSize) + "," + std::to_string(utils::datablock_size);
    seal_params_ = utils::create_encryption_parameters(selection, type);
    auto max_slots = PolyDegree;
    auto num_buckets = get_num_buckets();
    size_t num_slots_per_entry = get_num_slots_per_entry();
    if (type_ == UIUC) {
        set_first_dimension_size();
        size_t dim_size = get_first_dimension_size();
        size_t per_server_capacity = max_slots / dim_size;
        size_t num_servers = ceil(num_buckets * 1.0 / per_server_capacity);
        size_t num_slots_per_entry_rounded = utils::next_power_of_two(num_slots_per_entry);
        size_t num_chunk_ctx = ceil((num_slots_per_entry * 1.0) / dim_size);
        size_t row_size = PolyDegree / 2;
        size_t gap = row_size / dim_size;
        size_t merged_ctx_needed = ceil((num_servers * num_chunk_ctx * gap * num_slots_per_entry_rounded * 1.0) / row_size);

        query_size = {size_t(NumHashFunctions), num_servers, 3};
        response_size = {size_t(NumHashFunctions),  merged_ctx_needed};
    } else {
        size_t num_subbucket = max_slots / num_buckets;
        size_t subbucket_size = ceil(get_bucket_size() * 1.0 / num_subbucket);
        
        for (PIRANA_m = 2; utils::choose(PIRANA_m, PIRANA_k) < subbucket_size; PIRANA_m++); 

        query_size = {size_t(NumHashFunctions), 1, PIRANA_m};
        response_size = {size_t(NumHashFunctions),  num_slots_per_entry};
    }

    default_value_ = type == PIRANA ? 1 : std::numeric_limits<uint64_t>().max();

}

EncryptionParameters BatchPirParams::get_seal_parameters() const
{
    return seal_params_;
}

uint32_t BatchPirParams::get_num_slots_per_entry() {
    return ceil((utils::datablock_size * 1.0) / (seal_params_.plain_modulus().bit_count()-1));
}

int BatchPirParams::get_batch_size() {
    return batch_size_;
}

size_t BatchPirParams::get_num_buckets() {
    return ceil(CuckooFactor * batch_size_);
}

size_t BatchPirParams::get_bucket_size() {
    return ceil(CuckooFactorBucket * NumHashFunctions * DBSize / get_num_buckets());
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
    size_t dim_size = dim_size_;
    size_t prev_dim_size = dim_size;
    size_t batch_size = ceil((batch_size_*CuckooFactor)*1.0/2);
    while(batch_size * dim_size <= PolyDegree/2){
        prev_dim_size = dim_size;
        dim_size = utils::next_power_of_two(dim_size + 1);
    }
    dim_size_ = prev_dim_size;
}

void BatchPirParams::print_params() const {
std::cout << "+---------------------------------------------------+" << std::endl;
std::cout << "|                  Batch Parameters                 |" << std::endl;
std::cout << "+---------------------------------------------------+" << std::endl;
std::cout << std::left << std::setw(20) << "| NumHashFunctions: " << NumHashFunctions << std::endl;
std::cout << std::left << std::setw(20) << "| batch_size_: " << batch_size_ << std::endl;
std::cout << std::left << std::setw(20) << "| CuckooFactor: " << CuckooFactor << std::endl;
std::cout << std::left << std::setw(20) << "| DBSize: " << DBSize << std::endl;
std::cout << std::left << std::setw(20) << "| MaxAttempts: " << MaxAttempts << std::endl;
std::cout << "+---------------------------------------------------+" << std::endl;
}