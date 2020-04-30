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
#include "crypto/robust_multisig_aggregate.hpp"

#include "benchmark/benchmark.h"


constexpr uint32_t wallet_size = 1;

using fetch::byte_array::ByteArray;
using fetch::byte_array::ConstByteArray;


using namespace fetch::crypto::arms::mcl;

using RNG = fetch::random::LinearCongruentialGenerator;

namespace {

RNG rng;


void ARMS_Sign(benchmark::State &state)
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
        auto sign_index = static_cast<uint32_t>(rng() % transaction_size);
        state.ResumeTiming();

        // Compute signing
        SignProve(message, SK[sign_index], PK[sign_index], generator_g2);
    }
}



void ARMS_Verify(benchmark::State &state)
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
            auto sign_index = static_cast<uint32_t>(rng() % transaction_size);
            std::pair<Signature, Proof> sigma = SignProve(message, SK[sign_index], PK[sign_index], generator_g2);

            state.ResumeTiming();
            Verify(generator_g2, PK[sign_index], message, sigma.first, sigma.second);
        }
    }




    void ARMS_Verify_Slow(benchmark::State &state)
    {
        details::MCLInitialiser();
        GeneratorG2 generator_g2;
        SetGenerator(generator_g2);

        // Create keys
        uint32_t                  transaction_size = 20;
        auto                          wallet_size = static_cast<uint32_t>(state.range(0));

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
            auto sign_index = static_cast<uint32_t>(rng() % transaction_size);
            std::pair<Signature, Proof> sigma = SignProve(message, SK[sign_index], PK[sign_index], generator_g2);

            state.ResumeTiming();
            VerifySlow(PK[sign_index], message, sigma.first, generator_g2);

        }
    }



    void ARMS_Combine(benchmark::State &state)
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


            std::vector<std::pair<Signature, Proof>> sigmas;
            sigmas.resize(transaction_size);
            for (uint32_t i = 0; i < transaction_size; ++i) {
                std::pair<Signature, Proof> sigma = SignProve(messages[i], SK[i], PK[i], generator_g2);
                sigmas[i] = sigma;
            }

            std::vector<Signature> validSignatures;
            state.ResumeTiming();
            for (uint32_t i = 0; i < transaction_size; ++i){
              bool b = Verify(generator_g2, PK[i], messages[i], sigmas[i].first, sigmas[i].second);
              if (b) {
                  validSignatures.push_back(sigmas[i].first);
              }
            }
            AggregateSig(validSignatures);
        }
    }


    void ARMS_Combine_Slow(benchmark::State &state)
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

            std::vector<std::pair<Signature, Proof>> sigmas;
            sigmas.resize(transaction_size);

            for (uint32_t i = 0; i < transaction_size; ++i) {
                std::pair<Signature, Proof> sigma = SignProve(messages[i], SK[i], PK[i], generator_g2);
                sigmas[i] = sigma;
            }

            std::vector<Signature> validSignatures;
            state.ResumeTiming();
            for (uint32_t i = 0; i < transaction_size; ++i){
                bool b = VerifySlow(PK[i], messages[i], sigmas[i].first, generator_g2);
                if (b) {
                    validSignatures.push_back(sigmas[i].first);
                }
            }
            AggregateSig(validSignatures);
        }

    }


    void ARMS_VerifyAgg(benchmark::State &state)
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

            std::vector<Signature> signatures;
            signatures.resize(transaction_size);

            for (uint32_t i = 0; i < transaction_size; ++i) {
                std::pair<Signature, Proof> sigma = SignProve(messages[i], SK[i], PK[i], generator_g2);
                signatures[i] = sigma.first;
            }


            auto aggregate_signature = AggregateSig(signatures);

            state.ResumeTiming();

            VerifyAgg(messages, aggregate_signature, PK, generator_g2);
        }
    }

}  // namespace

BENCHMARK(ARMS_Sign)->RangeMultiplier(2)->Range(1, 1<<10);
BENCHMARK(ARMS_Verify)->RangeMultiplier(2)->Range(1, 1<<10);
BENCHMARK(ARMS_Verify_Slow)->RangeMultiplier(2)->Range(1, 1<<10);
BENCHMARK(ARMS_Combine)->RangeMultiplier(2)->Range(5, 5);
BENCHMARK(ARMS_Combine_Slow)->RangeMultiplier(2)->Range(5, 5);
BENCHMARK(ARMS_VerifyAgg)->RangeMultiplier(2)->Range(5, 5);