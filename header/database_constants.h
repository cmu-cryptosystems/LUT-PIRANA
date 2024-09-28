#ifndef DATABASE_CONSTANTS_H
#define DATABASE_CONSTANTS_H

#include <stdexcept>

enum BatchPirType {
    PIRANA, 
    UIUC
};

enum HashType {
    LowMC, 
    AES
};

namespace DatabaseConstants {

    constexpr int PolyDegree = 8192;
    constexpr int MaxAttempts = 500;
    constexpr int NumHashFunctions = 3;
    constexpr double CuckooFactor = 2.0; // < 2^{-54} failure prob. 
    constexpr double CuckooFactorBucket = 1.6; // 2^{-54} failure prob. 
    constexpr int OutputLength = LUT_OUTPUT_SIZE;
    constexpr int InputLength = LUT_INPUT_SIZE + 1;
    constexpr int pirana_k = 2;
    constexpr double FirstDimension = 32;
    // Ref: Table 1 in https://eprint.iacr.org/2017/299
    constexpr int MaxBucketSize = [](){
        switch (LUT_INPUT_SIZE) {
            case 16:
                return 74;
            case 20:
                return 556;
            case 24:
                return 6798;
            case 28:
                return 100890;
            default:
                throw std::runtime_error("Unsupported LUT_OUTPUT_SIZE");
        }
    }();
    constexpr int NumTaskGroups = 128; // used for combining parallelization with less memory consumption

}

#endif // DATABASE_CONSTANTS_H