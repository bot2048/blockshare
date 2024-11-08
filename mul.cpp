#include <iostream>
#include <iomanip>
#include <sstream>
#include <openssl/evp.h>
#include <random>
#include <pthread.h>
#include <atomic>
#include <string>
#include <cstdlib>

std::atomic<bool> found(false); // Atomic flag to signal when a match is found
std::pair<std::string, std::string> result; // Store the result

std::string generate_random_string(size_t length) {
    const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    std::default_random_engine rng(std::random_device{}());
    std::uniform_int_distribution<> dist(0, sizeof(charset) - 2);

    std::string random_str;
    for (size_t i = 0; i < length; ++i) {
        random_str += charset[dist(rng)];
    }
    return random_str;
}

std::string sha256(const std::string &str) {
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        throw std::runtime_error("Failed to create EVP_MD_CTX");
    }

    const EVP_MD *md = EVP_sha256();
    if (EVP_DigestInit_ex(mdctx, md, nullptr) != 1) {
        EVP_MD_CTX_free(mdctx);
        throw std::runtime_error("Failed to initialize digest");
    }

    if (EVP_DigestUpdate(mdctx, str.c_str(), str.size()) != 1) {
        EVP_MD_CTX_free(mdctx);
        throw std::runtime_error("Failed to update digest");
    }

    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len;
    if (EVP_DigestFinal_ex(mdctx, hash, &hash_len) != 1) {
        EVP_MD_CTX_free(mdctx);
        throw std::runtime_error("Failed to finalize digest");
    }

    EVP_MD_CTX_free(mdctx);

    std::stringstream ss;
    for (unsigned int i = 0; i < hash_len; ++i) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    return ss.str();
}

void* find_sha256_with_leading_zeros(void* args) {
    auto base_string = static_cast<std::pair<std::string, int>*>(args);
    std::string hash_value;

    while (!found) {
        std::string random_suffix = generate_random_string(10);
        std::string candidate = base_string->first + random_suffix;
        
        hash_value = sha256(candidate);

        if (hash_value.substr(0, base_string->second) == std::string(base_string->second, '0')) {
            if (!found.exchange(true)) { // Set flag if not already set
                result = {candidate, hash_value};
            }
            return nullptr;
        }
    }
    return nullptr;
}

int main(int argc, char* argv[]) {
    if (argc != 3) {
        std::cerr << "Usage: " << argv[0] << " <base_string> <k>" << std::endl;
        return 1;
    }

    std::string base_string = argv[1];
    int k = std::atoi(argv[2]); // Number of leading zeros
    int num_threads = 30; // Number of threads to run concurrently

    pthread_t threads[num_threads];
    std::pair<std::string, int> args = {base_string, k};

    for (int i = 0; i < num_threads; ++i) {
        if (pthread_create(&threads[i], nullptr, find_sha256_with_leading_zeros, &args) != 0) {
            std::cerr << "Error creating thread " << i << std::endl;
            return 1;
        }
    }

    for (int i = 0; i < num_threads; ++i) {
        pthread_join(threads[i], nullptr);
    }

    std::cout << "String: " << result.first << std::endl;
    std::cout << "SHA-256 Hash: " << result.second << std::endl;

    return 0;
}
