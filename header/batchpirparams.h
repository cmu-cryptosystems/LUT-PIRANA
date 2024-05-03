#ifndef BATCH_PIR_PARAMS_H
#define BATCH_PIR_PARAMS_H

#include <cstddef>
#include <cstdlib>
#include "database_constants.h"
#include "seal/seal.h"
using namespace seal;


class BatchPirParams {
public:
    BatchPirParams(int batch_size, bool parallel, BatchPirType type = PIRANA, HashType hash_type = LowMC, uint64_t pirana_k = 2);

    int get_batch_size();
    size_t get_num_buckets();
    size_t get_bucket_size();
    size_t get_first_dimension_size();
    uint64_t get_default_value();
    uint32_t get_num_slots_per_entry();
    seal::EncryptionParameters get_seal_parameters() const;
    bool is_parallel() {return parallel;}
    const BatchPirType get_type() {return type_;}
    const HashType get_hash_type() {return hash_type_;}
    const auto get_PIRANA_params() {return std::make_pair(PIRANA_m, PIRANA_k);}

    void set_first_dimension_size();
    void print_params() const;
    std::vector<size_t> query_size, response_size;
    uint64_t noise_bits;

private:
    int batch_size_= 0;
    size_t dim_size_= 1;
    uint64_t default_value_ = 0;
    seal::EncryptionParameters seal_params_;
    bool parallel;
    BatchPirType type_;
    HashType hash_type_;
    uint64_t PIRANA_m = 0;
    uint64_t PIRANA_k = 0;
};

#endif // BATCH_PIR_PARAMS_H
