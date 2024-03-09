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
    input_choices.push_back({256, 65536, 4});
    // input_choices.push_back({256, 1048576, 16});
    // input_choices.push_back({32, 1048576, 32});
    // input_choices.push_back({64, 1048576, 32});
    // input_choices.push_back({256, 1048576, 32});
    

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

    string selection = std::to_string(choice[0]) + "," + std::to_string(choice[1]) + "," + std::to_string(choice[2]);

    auto encryption_params = utils::create_encryption_parameters(selection);
    BatchPirParams params(choice[0], choice[1], choice[2], encryption_params);
    params.set_first_dimension_size();
    params.print_params();

    BatchPIRServer batch_server(params);
    auto start = chrono::high_resolution_clock::now();
    batch_server.initialize();
    #ifndef DEBUG 
    std::cout << "BatchPIRServer: Preparing PIR servers......" << std::endl;
    timing_start("Plaintext encoding");
    batch_server.prepare_pir_server();
    timing_end("Plaintext encoding");
    std::cout << "BatchPIRServer: PIR servers preparation complete." << std::endl;
    #endif
    auto end = chrono::high_resolution_clock::now();
    auto duration_init = chrono::duration_cast<chrono::milliseconds>(end - start);
    cout << "Main: Initialization complete for example " << (iteration + 1) << "." << endl;
    init_times.push_back(duration_init);

    BatchPIRClient batch_client(params);

    vector<rawdatablock> plain_queries(choice[0]);
    vector<vector<string>> batch(choice[0]);
    for (int i = 0; i < choice[0]; i++)
    {
        plain_queries[i] = rawdatablock(i);
        for (auto& cipher: batch_server.ciphers) {
            auto message = utils::concatenate(cipher.prefix, plain_queries[i]);
            auto ciphertext = cipher.encrypt(message).to_string();
            batch[i].push_back(ciphertext);
        }
    }

    cout << "Main: Starting query generation for example " << (iteration + 1) << "..." << endl;
    start = chrono::high_resolution_clock::now();
    auto queries = batch_client.create_queries(batch);
    end = chrono::high_resolution_clock::now();
    auto duration_querygen = chrono::duration_cast<chrono::milliseconds>(end - start);
    query_gen_times.push_back(duration_querygen);
    cout << "Main: Query generation complete for example " << (iteration + 1) << "." << endl;

    #ifdef DEBUG 
    batch_server.i_of_interest = 2;
    batch_server.iB_of_interest = batch_client.inv_cuckoo_map[batch_server.i_of_interest];
    batch_server.icol_of_interest = batch_client.bucket_to_position[batch_server.iB_of_interest];
    size_t x_of_interest = plain_queries[batch_server.i_of_interest].to_ullong();
    cout << fmt::format("debug example: i={}, B={}, x={}, nonce={}, \ncol=\n", batch_server.i_of_interest, batch_server.iB_of_interest, x_of_interest, batch_server.nonces[batch_server.iB_of_interest].to_string());
    for (auto col: batch_server.icol_of_interest) {
        cout << fmt::format("{}(= {}) \n", col, batch_server.buckets_[batch_server.iB_of_interest][col].to_string());
    }
    cout << endl;

    std::cout << "BatchPIRServer: Preparing PIR servers......" << std::endl;
    batch_server.prepare_pir_server();
    std::cout << "BatchPIRServer: PIR servers preparation complete." << std::endl;
    
    block mask_i = enc_masks[batch_server.i_of_interest];
    cout << fmt::format("encmask[{}, {}]={}\n", batch_server.iB_of_interest, x_of_interest, mask_i.to_string()); // H (j, x)
    for (auto [bucket, value]: batch_server.encryption_array[x_of_interest]) {
        cout << fmt::format("encrypt[{}, {}]={}\n", bucket, x_of_interest, value.to_string());
    }

    int f = 0;
    for (auto col: batch_server.icol_of_interest) {
        if(utils::split(mask_i ^ batch_server.buckets_[batch_server.iB_of_interest][col]).first == batch_server.nonces[batch_server.iB_of_interest]) {
            f++;
        }
    }
    if (f!=1) {
        throw std::runtime_error("Error: Mask incorrect");
    }

    #endif

    batch_server.set_client_keys(client_id, batch_client.get_public_keys());
    
    cout << "Main: Starting response generation for example " << (iteration + 1) << "..." << endl;
    start = chrono::high_resolution_clock::now();
    vector<PIRResponseList> responses = batch_server.generate_response(client_id, queries);
    end = chrono::high_resolution_clock::now();
    auto duration_respgen = chrono::duration_cast<chrono::milliseconds>(end - start);
    resp_gen_times.push_back(duration_respgen);
    cout << "Main: Response generation complete for example " << (iteration + 1) << "." << endl;
    
    #ifdef DEBUG 
    if (DatabaseConstants::type == PIRANA) {
        Plaintext pt;
        cout << "Checking masks......" << endl;
        for (int hash_idx=0; hash_idx<params.get_num_hash_funcs(); hash_idx++) {
            batch_server.evaluator_->transform_from_ntt_inplace(batch_server.mq[hash_idx]);
            batch_client.decryptor_->decrypt(batch_server.mq[hash_idx], pt);
            vector<uint64_t> plain_entry(params.get_num_buckets());
            batch_client.batch_encoder_->decode(pt, plain_entry);
            auto column = batch_server.icol_of_interest[hash_idx];
            for (int row = 0; row < params.get_num_buckets(); row++) {
                if (plain_entry[row] != (batch_client.bucket_to_position[row][hash_idx] == column)) {
                    cerr << fmt::format("Error: {} {} {}", row, column, row) << endl;
                    exit(1);
                }
            }
        }
        
        cout << "Checking masked values......" << endl;
        vector<vector<uint64_t>> plain_masked_value(params.get_num_hash_funcs(), vector<uint64_t>(params.get_num_buckets()));
        for (int hash_idx=0; hash_idx<params.get_num_hash_funcs(); hash_idx++) {
            for (int slot_idx = 0; slot_idx < params.get_num_slots_per_entry(); slot_idx++) {
                batch_server.evaluator_->transform_from_ntt_inplace(batch_server.mv[hash_idx][slot_idx]);
                batch_client.decryptor_->decrypt(batch_server.mv[hash_idx][slot_idx], pt);
                batch_client.batch_encoder_->decode(pt, plain_masked_value[hash_idx]);

                if (plain_masked_value[hash_idx][batch_server.iB_of_interest] != batch_server.plain_col_of_interest[hash_idx][slot_idx]) {
                    throw std::runtime_error(
                        fmt::format("Error: {} {}", plain_masked_value[hash_idx][batch_server.iB_of_interest], batch_server.plain_col_of_interest[hash_idx][slot_idx])
                    );
                }
            }
        }
        
        cout << "Checking raw responses......" << endl;
        for (int hash_idx=0; hash_idx<params.get_num_hash_funcs(); hash_idx++) {
            for (int slot_idx = 0; slot_idx < params.get_num_slots_per_entry(); slot_idx++) {
                batch_client.decryptor_->decrypt(responses[hash_idx][slot_idx], pt);
                vector<uint64_t> plain_entry(params.get_num_buckets());
                batch_client.batch_encoder_->decode(pt, plain_entry);
                if (batch_server.plain_col_of_interest[hash_idx][slot_idx] != plain_entry[batch_server.iB_of_interest]) {
                    throw std::runtime_error(
                        fmt::format("Error: {} {}", plain_masked_value[hash_idx][batch_server.iB_of_interest], plain_entry[batch_server.iB_of_interest])
                    );
                }
            }
        }
            
    }

    batch_client.server = &batch_server;
    #endif

    cout << "Main: Checking decoded entries for example " << (iteration + 1) << "..." << endl;
    auto decode_responses = batch_client.decode_responses(responses);

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
