#include <cassert>
#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Crypto/PRNG.h>
#include <iostream>
#include <cstdlib>
#include <chrono>
#include <seal/evaluator.h>
#include "batchpirparams.h"
#include "batchpirserver.h"
#include "batchpirclient.h"

using namespace std;
using namespace chrono;

void print_usage()
{
    std::cout << "Usage: vectorized_batch_pir -n <db_entries> -s <entry_size>\n";
}

bool validate_arguments(int argc, char *argv[], size_t &db_entries, size_t &entry_size)
{
    if (argc == 2 && string(argv[1]) == "-h")
    {
        print_usage();
        return false;
    }
    if (argc != 5 || string(argv[1]) != "-n" || string(argv[3]) != "-s")
    {
        std::cerr << "Error: Invalid arguments.\n";
        print_usage();
        return false;
    }
    db_entries = stoull(argv[2]);
    entry_size = stoull(argv[4]);
    return true;
}

int batchpir_main(int argc, char* argv[])
{
    srand(1);
    const int client_id = 0;
    //  batch size, number of entries, size of entry
    std::vector<std::array<size_t, 3>> input_choices;
    input_choices.push_back({4096, 1 << DatabaseConstants::OutputLength, DatabaseConstants::OutputLength / 4});

    std::vector<std::chrono::milliseconds> init_times;
    std::vector<std::chrono::milliseconds> query_gen_times;
    std::vector<std::chrono::milliseconds> resp_gen_times;
    std::vector<size_t> communication_list;

 for (size_t iteration = 0; iteration < input_choices.size(); ++iteration)
{
    std::cout << "***************************************************" << std::endl;
    std::cout << "             Starting example " << (iteration + 1) << "               " << std::endl;
    std::cout << "***************************************************" << std::endl;

    const auto& choice = input_choices[iteration];

    BatchPirParams params(choice[0], true, PIRANA, HashType::LowMC);
    params.print_params();

    osuCrypto::PRNG prng(osuCrypto::sysRandomSeed());

    keyblock lowmc_key; 
    prefixblock lowmc_prefix; 
    oc::block aes_key;
    std::bitset<128-DatabaseConstants::InputLength> aes_prefix;

    if (params.get_hash_type() == HashType::LowMC) {
        lowmc_key = random_bitset<keysize>(&prng);
        lowmc_prefix = random_bitset<prefixsize>(&prng);
    } else {
        aes_key = prng.get<oc::block>();
        aes_prefix = random_bitset<128-DatabaseConstants::InputLength>(&prng);
    }

    BatchPIRServer batch_server(params, prng);
    BatchPIRClient batch_client(params);

    cout << "Main: Populating Raw DB " << (iteration + 1) << "." << endl;
    batch_server.populate_raw_db();
    cout << "Main: Initialization start " << (iteration + 1) << "." << endl;
    auto start = chrono::high_resolution_clock::now();

    if (params.get_hash_type() == HashType::LowMC) {
        batch_server.lowmc_prepare(lowmc_key, lowmc_prefix);
    } else {
        batch_server.aes_prepare(aes_key, aes_prefix);
    }

    batch_server.initialize();
    auto end = chrono::high_resolution_clock::now();
    auto duration_init = chrono::duration_cast<chrono::milliseconds>(end - start);
    cout << "Main: Initialization complete for example " << (iteration + 1) << "." << endl;
    init_times.push_back(duration_init);

    // preparing queries
    vector<rawinputblock> plain_queries(choice[0]);
    vector<string> batch(choice[0]);
    for (int i = 0; i < choice[0]; i++)
    {
        plain_queries[i] = rawinputblock(i);
        if (params.get_hash_type() == HashType::LowMC) {
            auto message = utils::concatenate(lowmc_prefix, plain_queries[i]);
            batch[i] = batch_server.lowmc_oprf->encrypt(message).to_string();
        } else {
            auto message_string = concatenate(aes_prefix, plain_queries[i]).to_string();
            uint64_t high_half = std::bitset<64>(message_string.substr(0, 64)).to_ullong();
            uint64_t low_half = std::bitset<64>(message_string.substr(64)).to_ullong();
            oc::block message(high_half, low_half);
            auto c = batch_server.aes_oprf->ecbEncBlock(message).get<uint64_t>();
            batch[i] = std::bitset<64>(c[1]).to_string() + std::bitset<64>(c[0]).to_string();
        }
    }

    cout << "Main: Starting query generation for example " << (iteration + 1) << "..." << endl;
    start = chrono::high_resolution_clock::now();
    auto queries = batch_client.create_queries(batch);
    auto query_buffer = batch_client.serialize_query(queries);
    end = chrono::high_resolution_clock::now();
    auto duration_querygen = chrono::duration_cast<chrono::milliseconds>(end - start);
    query_gen_times.push_back(duration_querygen);
    cout << "Main: Query generation complete for example " << (iteration + 1) << "." << endl;

    auto key_buffer = batch_client.get_public_keys();
    batch_server.set_client_keys(client_id, key_buffer);
    
    cout << "Main: Starting response generation for example " << (iteration + 1) << "..." << endl;
    start = chrono::high_resolution_clock::now();
    auto queries_deserialized = batch_server.deserialize_query(query_buffer);
    vector<PIRResponseList> responses = batch_server.generate_response(client_id, queries_deserialized);
    auto response_buffer = batch_server.serialize_response(responses);
    end = chrono::high_resolution_clock::now();
    auto duration_respgen = chrono::duration_cast<chrono::milliseconds>(end - start);
    resp_gen_times.push_back(duration_respgen);
    cout << "Main: Response generation complete for example " << (iteration + 1) << "." << endl;

    cout << "Main: Checking decoded entries for example " << (iteration + 1) << "..." << endl;
    timing_start("Decoding");
    auto responses_deserialized = batch_client.deserialize_response(response_buffer);
    auto decode_responses = batch_client.decode_responses(responses_deserialized);
    timing_end("Decoding");

    communication_list.push_back(batch_client.get_serialized_commm_size());

    if (batch_server.check_decoded_entries(decode_responses, plain_queries, batch_client.cuckoo_map))
    {
        cout << "Main: All the entries matched for example " << (iteration + 1) << "!!" << endl;
    }

    cout << endl;
}


    cout << "***********************" << endl;
    cout << "     Timings Report    " << endl;
    cout << "***********************" << endl;
    for (size_t i = 0; i < input_choices.size(); ++i)
    {
        cout << "Input Parameters: ";
        cout << "Batch Size: " << input_choices[i][0] << ", ";
        cout << "Number of Entries: " << input_choices[i][1] << ", ";
        cout << "Entry Size: " << input_choices[i][2] << endl;

        cout << "Initialization time: " << init_times[i].count() << " milliseconds" << endl;
        cout << "Query generation time: " << query_gen_times[i].count() << " milliseconds" << endl;
        cout << "Response generation time: " << resp_gen_times[i].count() << " milliseconds" << endl;
        cout << "Total communication: " << communication_list[i] << " KB" << endl;
        cout << endl;
    }

    return 0;
}



int main(int argc, char *argv[])
{
    batchpir_main(argc, argv);
    return 0;
}
