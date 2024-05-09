#ifndef DATABASE_CONSTANTS_H
#define DATABASE_CONSTANTS_H

#include <limits>
#include <cstdint>
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
    constexpr int PlaintextModBitss = 22;
    constexpr int MaxAttempts = 500;
    constexpr int NumHashFunctions = 3;
    constexpr double CuckooFactor = 2.0; // < 2^{-54} failure prob. 
    constexpr double CuckooFactorBucket = 1.6; // 2^{-54} failure prob. 
    constexpr int OutputLength = LUT_OUTPUT_SIZE;
    constexpr int DBSize = 1 << OutputLength;
    constexpr int InputLength = OutputLength + 1;
    constexpr int BucketHashLength = 32;
    constexpr double FirstDimension = 32;
    constexpr int MaxBucketSize = [](){
        switch (LUT_OUTPUT_SIZE) {
            case 16:
                return 74;
            case 20:
                return 556;
            case 24:
                return 6798;
            default:
                throw std::runtime_error("Unsupported LUT_OUTPUT_SIZE");
        }
    }();

}

#endif // DATABASE_CONSTANTS_H