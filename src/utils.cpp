#include "utils.h"
#include <chrono>
#include <seal/util/hestdparms.h>
#include "seal/util/polyarithsmallmod.h"

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

    bool cuckoo_insert(uint64_t key, size_t attempt, std::vector<std::vector<size_t>>& key_to_buckets, std::unordered_map<uint64_t, uint64_t> &bucket_to_key)
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


    // sample r <- [0, 2^{nbits})
    void SampleLimbs(std::vector<uint64_t>& dest,
                    const seal::EncryptionParameters& parms, size_t nbits,
                    std::shared_ptr<seal::UniformRandomGenerator> prng) {
        const auto& coeff_modulus = parms.coeff_modulus();
        size_t num_modulus = coeff_modulus.size();
        size_t logQ = 0;
        for (const auto& p : coeff_modulus) {
            logQ += p.bit_count();
        }
        size_t coeff_count = dest.size() / num_modulus;
        size_t numelt = seal::util::mul_safe(coeff_count, num_modulus);
        assert (dest.size() == numelt);
        assert (nbits > 0 && logQ > nbits);

        const size_t num_limbs = (nbits + 63) / 64UL;
        const uint64_t msb_mask =
            (static_cast<uint64_t>(1) << (nbits - 64 * (num_limbs - 1))) - 1;
        size_t rnd_byte_count = seal::util::mul_safe(num_limbs, sizeof(uint64_t));

        if (!prng) {
            prng = parms.random_generator()->create();
        }

        auto* dest_ptr = dest.data();
        for (size_t i = 0; i < coeff_count; ++i) {
            prng->generate(rnd_byte_count,
                        reinterpret_cast<seal::seal_byte*>(dest_ptr));
            dest_ptr[num_limbs - 1] &= msb_mask;
            std::fill_n(dest_ptr + num_limbs, num_modulus - num_limbs, 0);
            dest_ptr += num_modulus;
        }
    }

    void SampleRanomRNS(std::vector<uint64_t>& dest,
                    const seal::SEALContext::ContextData& context, size_t nbits,
                    bool is_ntt,
                    std::shared_ptr<seal::UniformRandomGenerator> prng) {
        const auto& modulus = context.parms().coeff_modulus();
        const auto* bigQ = context.total_coeff_modulus();
        size_t num_modulus = modulus.size();
        size_t n = dest.size() / num_modulus;
        size_t N = context.parms().poly_modulus_degree();
        assert(n > 0 && n <= N);
        if (is_ntt) {
            assert(n == N);
        }

        nbits = nbits + 1;
        // sample [0, 2^nbits)
        SampleLimbs(dest, context.parms(), nbits, prng);

        std::vector<uint64_t> neg_threshold(num_modulus, 0);  // 2^{nbits-1}
        std::vector<uint64_t> neg_shift(num_modulus, 0);      // Q - 2^{nbits}
        {
            const size_t num_limbs = (nbits + 63) / 64UL;
            std::vector<uint64_t> upper(num_modulus, 0);
            upper[num_limbs - 1] = 1UL << (nbits - 64 * (num_limbs - 1));
            neg_threshold[num_limbs - 1] = upper[num_limbs - 1] >> 1;
            seal::util::sub_uint(bigQ, upper.data(), num_modulus, neg_shift.data());
        }

        auto* limb_ptr = dest.data();
        for (size_t i = 0; i < n; ++i) {
            if (seal::util::is_greater_than_or_equal_uint(
                    limb_ptr, neg_threshold.data(), num_modulus)) {
            // x >= 2^{nbits-1} is converted as Q - 2^{nbits} + x
            seal::util::add_uint(neg_shift.data(), limb_ptr, num_modulus, limb_ptr);
            }
            limb_ptr += num_modulus;
        }

        const auto* rns_tool = context.rns_tool();
        assert(rns_tool != nullptr);
        assert(rns_tool->base_q() != nullptr);
        // limbs form to rns form
        rns_tool->base_q()->decompose_array(dest.data(), n,
                                            seal::MemoryManager::GetPool());

        if (is_ntt) {
            const auto* ntt_tables = context.small_ntt_tables();
            auto* dest_ptr = dest.data();
            for (size_t j = 0; j < num_modulus; ++j) {
            seal::util::ntt_negacyclic_harvey(dest_ptr, ntt_tables[j]);
            dest_ptr += N;
            }
        }
    }

    void NoiseFloodInplace(Ciphertext &ct, const SEALContext &context, size_t noise_bits) {
        assert(seal::is_metadata_valid_for(ct, context));
        assert(ct.size() == 2);
        auto context_data = context.get_context_data(ct.parms_id());
        assert(context_data.get() != nullptr);

        size_t num_coeffs = ct.poly_modulus_degree();
        size_t num_modulus = ct.coeff_modulus_size();
        const auto &modulus = context_data->parms().coeff_modulus();

        std::vector<uint64_t> wide_noise(num_coeffs * num_modulus);

        // sample r from [-2^{k-1}, 2^{k-1}]
        SampleRanomRNS(wide_noise, *context_data, noise_bits - 1, ct.is_ntt_form());

        seal::util::add_poly_coeffmod(
            {wide_noise.data(), num_coeffs},
            {ct.data(0), num_coeffs}, 
            num_modulus, 
            modulus,
            {ct.data(0), num_coeffs});
    
    }


}