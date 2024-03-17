#ifndef DATABASE_CONSTANTS_H
#define DATABASE_CONSTANTS_H

#include <limits>
#include <cstdint>

enum BatchPirType {
    PIRANA, 
    UIUC
};

#ifndef output_length
#define output_length 16
#endif

namespace DatabaseConstants {

    constexpr int PolyDegree = 8192;
    constexpr int PlaintextModBitss = 22;
    constexpr int MaxAttempts = 500;
    constexpr int NumHashFunctions = 3;
    constexpr double CuckooFactor = 1.2;
    constexpr double CuckooFactorBucket = 1.4;
    constexpr int OutputLength = output_length;
    constexpr int InputLength = OutputLength + 1;
    constexpr int BucketHashLength = 32;
    constexpr double FirstDimension = 32;

}

#endif // DATABASE_CONSTANTS_H