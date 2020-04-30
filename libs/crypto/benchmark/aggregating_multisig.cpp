//------------------------------------------------------------------------------
//
//   Copyright 2018-2020 Fetch.AI Limited
//
//   Licensed under the Apache License, Version 2.0 (the "License");
//   you may not use this file except in compliance with the License.
//   You may obtain a copy of the License at
//
//       http://www.apache.org/licenses/LICENSE-2.0
//
//   Unless required by applicable law or agreed to in writing, software
//   distributed under the License is distributed on an "AS IS" BASIS,
//   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//   See the License for the specific language governing permissions and
//   limitations under the License.
//
//------------------------------------------------------------------------------

#include "core/byte_array/byte_array.hpp"
#include "core/random/lcg.hpp"
#include "crypto/aggregating_multisig.hpp"

#include "benchmark/benchmark.h"


constexpr uint32_t wallet_size = 1;

using fetch::byte_array::ByteArray;
using fetch::byte_array::ConstByteArray;


using namespace fetch::crypto::amsp::mcl;

using RNG = fetch::random::LinearCongruentialGenerator;

namespace {

RNG rng;


void AMSP_Sign(benchmark::State &state)
{
    details::MCLInitialiser();
    GeneratorG2 generator_g2;
    SetGenerator(generator_g2);

    // Create keys
   uint32_t                   transaction_size = 20;
   auto                    wallet_size = static_cast<uint32_t>(state.range(0));

    std::vector<std::vector<PrivateKey>>           SK;
    std::vector<std::vector<PublicKey>>            PK;

    SK.resize(transaction_size);
    PK.resize(transaction_size);
    for (uint32_t i = 0; i<transaction_size; i++)
    {
        SK[i].resize(wallet_size);
        PK[i].resize(wallet_size);
    }

    for (uint32_t i = 0; i < transaction_size; i++)
    {
        for (uint32_t j = 0; j < wallet_size; j++)
        {
            auto new_keys                         = GenerateKeyPair(generator_g2);
            SK[i][j] = new_keys.first;
            PK[i][j] = new_keys.second;
        }
    }


    for (auto _ : state)
    {
        state.PauseTiming();
        std::string message{"hello" + std::to_string(rand() * rand())};

        auto i = static_cast<uint32_t>(rng() % transaction_size);

        state.ResumeTiming();

        std::vector<PrivateKey> coefficients = AggregateCoefficients(PK[i]);
        PublicKey aggregate_public_key = AggregatePublicKey(PK[i], coefficients);
        std::vector<Signature> signatures;
        for (uint32_t j = 0; j < wallet_size; j++){
            Signature sig = Sign(message, SK[i][j], coefficients[j], aggregate_public_key);
            signatures.push_back(sig);
        }
        MultiSig(signatures);
    }
}



void AMSP_VerifyMulti(benchmark::State &state)
    {
        details::MCLInitialiser();
        GeneratorG2 generator_g2;
        SetGenerator(generator_g2);

        // Create keys
        uint32_t                  transaction_size = 20;
        auto                      wallet_size = static_cast<uint32_t>(state.range(0));

        std::vector<std::vector<PrivateKey>>           SK;
        std::vector<std::vector<PublicKey>>            PK;

        SK.resize(transaction_size);
        PK.resize(transaction_size);
        for (uint32_t i = 0; i<transaction_size; i++)
        {
            SK[i].resize(wallet_size);
            PK[i].resize(wallet_size);
        }

        for (uint32_t i = 0; i < transaction_size; i++)
        {
            for (uint32_t j = 0; j < wallet_size; j++)
            {
                auto new_keys                         = GenerateKeyPair(generator_g2);
                SK[i][j] = new_keys.first;
                PK[i][j] = new_keys.second;
            }
        }


        for (auto _ : state)
        {
            state.PauseTiming();
            std::string message{"hello" + std::to_string(rand() * rand())};

            auto i = static_cast<uint32_t>(rng() % transaction_size);

            std::vector<PrivateKey> coefficients = AggregateCoefficients(PK[i]);
            PublicKey aggregate_public_key = AggregatePublicKey(PK[i], coefficients);
            std::vector<Signature> signatures;
            for (uint32_t j = 0; j < wallet_size; j++){
                Signature sig = Sign(message, SK[i][j], coefficients[j], aggregate_public_key);
                signatures.push_back(sig);
            }
            Signature sigma = MultiSig(signatures);

            state.ResumeTiming();
            VerifyMulti(PK[i], message, sigma, generator_g2);
        }
    }





    void AMSP_Aggregate(benchmark::State &state)
    {
        details::MCLInitialiser();
        GeneratorG2 generator_g2;
        SetGenerator(generator_g2);

        // Create keys
        uint32_t                  transaction_size = static_cast<uint32_t>(state.range(0));
 //       auto                      wallet_size

        std::vector<std::vector<PrivateKey>>           SK;
        std::vector<std::vector<PublicKey>>            PK;
//        std::vector<PrivateKey>                 fast_keys;

        SK.resize(transaction_size);
        PK.resize(transaction_size);
//        fast_keys.resize(transaction_size);

        for (uint32_t i = 0; i<transaction_size; i++)
        {
            SK[i].resize(wallet_size);
            PK[i].resize(wallet_size);
        }

        for (uint32_t i = 0; i < transaction_size; i++)
        {
            for (uint32_t j = 0; j < wallet_size; j++)
            {
                auto new_keys                         = GenerateKeyPair(generator_g2);
                SK[i][j] = new_keys.first;
                PK[i][j] = new_keys.second;

   //             bn::Fr::add(fast_keys[i], fast_keys[i], SK[i][j]);
            }
        }

        for (auto _ : state)
        {
            state.PauseTiming();

            std::vector<MessagePayload>                          messages;
            messages.resize(transaction_size);
            for (uint32_t i = 0; i<transaction_size; i++){
                messages[i] = "transaction" + std::to_string(rand() * rand());
            }



            std::vector<Signature> sigmas;
            sigmas.resize(transaction_size);
            for (uint32_t i = 0; i < transaction_size; ++i) {
                std::vector<PrivateKey> coefficients = AggregateCoefficients(PK[i]);
                PublicKey aggregate_public_key = AggregatePublicKey(PK[i], coefficients);

                std::vector<Signature> signatures;
                for (uint32_t j = 0; j < wallet_size; j++){
                    Signature sig = Sign(messages[i], SK[i][j], coefficients[j], aggregate_public_key);
                    signatures.push_back(sig);
                }
                sigmas[i] = MultiSig(signatures);
            }



            std::vector<Signature> validSignatures;
            state.ResumeTiming();
            for (uint32_t i = 0; i < transaction_size; ++i){
              bool b = VerifyMulti(PK[i], messages[i], sigmas[i], generator_g2);
              if (b) {
                  validSignatures.push_back(sigmas[i]);
              }
            }
            AggregateSig(validSignatures);
        }
    }



    void AMSP_VerifyAgg(benchmark::State &state)
    {
        details::MCLInitialiser();
        GeneratorG2 generator_g2;
        SetGenerator(generator_g2);

        // Create keys
        auto                   transaction_size = static_cast<uint32_t>(state.range(0));
//        uint32_t                          wallet_size = 5;

        std::vector<std::vector<PrivateKey>>           SK;
        std::vector<std::vector<PublicKey>>            PK;

        SK.resize(transaction_size);
        PK.resize(transaction_size);
        for (uint32_t i = 0; i<transaction_size; i++)
        {
            SK[i].resize(wallet_size);
            PK[i].resize(wallet_size);
        }

        for (uint32_t i = 0; i < transaction_size; i++)
        {
            for (uint32_t j = 0; j < wallet_size; j++)
            {
                auto new_keys                         = GenerateKeyPair(generator_g2);
                SK[i][j] = new_keys.first;
                PK[i][j] = new_keys.second;
            }
        }




        for (auto _ : state)
        {
            state.PauseTiming();

            std::vector<MessagePayload>                          messages;
            messages.resize(transaction_size);
            for (uint32_t i = 0; i<transaction_size; i++){
                messages[i] = "transaction" + std::to_string(rand() * rand());
            }

            std::vector<Signature> sigmas;
            sigmas.resize(transaction_size);
            for (uint32_t i = 0; i < transaction_size; ++i) {
                std::vector<PrivateKey> coefficients = AggregateCoefficients(PK[i]);
                PublicKey aggregate_public_key = AggregatePublicKey(PK[i], coefficients);

                std::vector<Signature> signatures;
                for (uint32_t j = 0; j < wallet_size; j++){
                    Signature sig = Sign(messages[i], SK[i][j], coefficients[j], aggregate_public_key);
                    signatures.push_back(sig);
                }
                sigmas[i] = MultiSig(signatures);
            }

            std::vector<Signature> validSignatures;
            for (uint32_t i = 0; i < transaction_size; ++i){
                bool b = VerifyMulti(PK[i], messages[i], sigmas[i], generator_g2);
                if (b) {
                    validSignatures.push_back(sigmas[i]);
                }
            }

            auto aggregate_signature = AggregateSig(validSignatures);

            state.ResumeTiming();

            VerifyAgg(messages, aggregate_signature, PK, generator_g2);
        }
    }

}  // namespace



// For more complex patterns of inputs, passing a custom function
// to Apply allows programmatic specification of an
// arbitrary set of arguments to run the microbenchmark on.
// The following example enumerates a dense range on
// one parameter, and a sparse range on the second.
//static void CustomArguments(benchmark::internal::Benchmark* b) {
//    for (int i = 1; i <= 1024; i = i + 5)
//            b->Args({i});
//}

//BENCHMARK(AMSP_Sign)->Apply(CustomArguments);
BENCHMARK(AMSP_Sign)->RangeMultiplier(2)->Range(1, 1<<10);
BENCHMARK(AMSP_VerifyMulti)->RangeMultiplier(2)->Range(1, 1<<10);
BENCHMARK(AMSP_Aggregate)->RangeMultiplier(2)->Range(5, 5);
BENCHMARK(AMSP_VerifyAgg)->RangeMultiplier(2)->Range(5, 5);