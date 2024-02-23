#ifndef DATABASE_CONSTANTS_H
#define DATABASE_CONSTANTS_H

#include <limits>
#include <cstdint>

#define DEBUG 1

namespace DatabaseConstants {

    constexpr int PolyDegree = 8192;
    constexpr int PlaintextModBitss = 22;
    constexpr int MaxAttempts = 500;
    constexpr int NumHashFunctions = 3;
    constexpr double CuckooFactor = 1.5;
    constexpr double CuckooFactorBucket = 2;
    constexpr int OutputLength = 16;
    constexpr int BucketHashLength = 32;
    constexpr double FirstDimension = 32;
    constexpr bool parallel = true;
    constexpr uint64_t DefaultVal =  1;
    constexpr uint64_t PIRANA_m = 21;
    constexpr uint64_t PIRANA_k = 2;

}

#endif // DATABASE_CONSTANTS_H