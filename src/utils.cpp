#include "utils.h"
#include <chrono>

using namespace std::chrono;

namespace utils {
    std::map<string, time_point<system_clock, nanoseconds>> start_timestamps;
    void timing_start(string prefix) {
        start_timestamps[prefix] = high_resolution_clock::now();
    }

    void timing_end(string prefix) {
        auto end = chrono::high_resolution_clock::now();
        auto duration_init = chrono::duration_cast<chrono::nanoseconds>(end - start_timestamps[prefix]);
        std::cout << fmt::format("{}: {:.3f} ms. ", prefix, duration_init.count() * 1.0 / 1e6) << std::endl;
        start_timestamps.erase(prefix);
    }

    uint64_t choose(uint64_t n, uint64_t k) {
        if (k > n) {
            return 0;
        }
        uint64_t r = 1;
        for (uint64_t d = 1; d <= k; ++d) {
            r *= n--;
            r /= d;
        }
        return r;
    }

    std::vector<uint64_t> get_perfect_constant_weight_codeword(uint64_t __number, uint64_t encoding_size, uint64_t hamming_weight, bool __verbose){
        vector<uint64_t> ans(encoding_size, 0ULL);
        uint64_t mod_size = choose(encoding_size, hamming_weight);
        if (__number >= mod_size){
            if (__verbose) 
                cout << "Overflow occurred, everything okay?" << endl;
            __number %= mod_size;
        }
        long remainder = __number, k_prime = hamming_weight;
        for (long pointer=encoding_size-1; pointer>=0; pointer--){
            if (remainder >= choose(pointer, k_prime)){
                ans[pointer] = 1ULL;
                remainder -= choose(pointer, k_prime);
                k_prime -= 1;
            }
        }
        return ans;
    }

    bool cuckoo_insert(uint64_t key, size_t attempt, std::unordered_map<uint64_t, std::vector<size_t>>& key_to_buckets, std::unordered_map<uint64_t, uint64_t> &bucket_to_key)
    {
        if (attempt > DatabaseConstants::MaxAttempts)
        {
            throw std::invalid_argument("Error: Cuckoo hashing failed");
            return false;
        }

        for (auto v : key_to_buckets[key])
        {
            if (bucket_to_key.find(v) == bucket_to_key.end())
            {
                bucket_to_key[v] = key;
                return true;
            }
        }

        std::vector<size_t> candidate_buckets = key_to_buckets[key];
        int idx = rand() % candidate_buckets.size();
        auto picked_bucket = candidate_buckets[idx];
        auto old = bucket_to_key[picked_bucket];
        bucket_to_key[picked_bucket] = key;

        cuckoo_insert(old, attempt + 1, key_to_buckets, bucket_to_key);
        return true;
    }
}