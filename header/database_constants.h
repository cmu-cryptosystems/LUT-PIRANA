#ifndef DATABASE_CONSTANTS_H
#define DATABASE_CONSTANTS_H

#include <limits>
#include <cstdint>

enum BatchPirType {
    PIRANA, 
    UIUC
};

namespace DatabaseConstants {

    constexpr BatchPirType type = PIRANA;
    constexpr int PolyDegree = 8192;
    constexpr int PlaintextModBitss = 22;
    constexpr int MaxAttempts = 500;
    constexpr int NumHashFunctions = 3;
    constexpr double CuckooFactor = 1.2;
    constexpr double CuckooFactorBucket = 1.4;
    constexpr int OutputLength = 16;
    constexpr int BucketHashLength = 32;
    constexpr double FirstDimension = 32;
    constexpr bool parallel = true;
    constexpr uint64_t DefaultVal = type == PIRANA ? 1 : std::numeric_limits<uint64_t>().max();
    constexpr uint64_t PIRANA_m = 9;
    constexpr uint64_t PIRANA_k = 2;

}

#endif // DATABASE_CONSTANTS_H