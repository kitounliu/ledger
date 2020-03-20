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
#include "crypto/robust_multisig.hpp"

#include "benchmark/benchmark.h"

using fetch::byte_array::ByteArray;
using fetch::byte_array::ConstByteArray;


using namespace fetch::crypto::rsms::mcl;

using RNG = fetch::random::LinearCongruentialGenerator;

namespace {

RNG rng;

void RSMS_SignProve(benchmark::State &state)
{
  details::MCLInitialiser();
  GeneratorG2 generator_g2;
  SetGenerator(generator_g2);

  // Create keys
  auto                   cabinet_size = static_cast<uint32_t>(state.range(0));

  std::vector<PublicVerifyKey>      public_verify_keys;
  std::vector<PrivateKey>           private_keys;
  GroupPublicKey                    group_public_key;

  private_keys.resize(cabinet_size);
  public_verify_keys.resize(cabinet_size);

    for (uint32_t i = 0; i < cabinet_size; ++i)
    {
        auto new_keys                         = GenerateKeyPair(generator_g2);
        private_keys[i] = new_keys.first;
        public_verify_keys[i] = new_keys.second;
    }

    group_public_key.GroupSet(public_verify_keys, generator_g2);

  for (auto _ : state)
  {
    state.PauseTiming();
    std::string message{"hello" + std::to_string(rand() * rand())};
    auto sign_index = static_cast<uint32_t>(rng() % cabinet_size);
    state.ResumeTiming();

    // Compute signing
//    Signature signature = Sign(group_public_key.aggregate_public_key, message, private_keys[sign_index], generator_g2);
//    Prove(group_public_key.public_verify_key_list[sign_index], group_public_key.aggregate_public_key, message, signature, private_keys[sign_index]);

    SignProve(group_public_key.public_verify_key_list[sign_index], group_public_key.aggregate_public_key, message, private_keys[sign_index]);

  }
}



void RSMS_Verify(benchmark::State &state)
    {
        details::MCLInitialiser();
        GeneratorG2 generator_g2;
        SetGenerator(generator_g2);

        // Create keys
        auto                   cabinet_size = static_cast<uint32_t>(state.range(0));

        std::vector<PublicVerifyKey>      public_verify_keys;
        std::vector<PrivateKey>           private_keys;
        GroupPublicKey                    group_public_key;

        private_keys.resize(cabinet_size);
        public_verify_keys.resize(cabinet_size);

        for (uint32_t i = 0; i < cabinet_size; ++i)
        {
            auto new_keys                         = GenerateKeyPair(generator_g2);
            private_keys[i] = new_keys.first;
            public_verify_keys[i] = new_keys.second;
        }

        group_public_key.GroupSet(public_verify_keys, generator_g2);

        for (auto _ : state)
        {
            state.PauseTiming();
            std::string message{"hello" + std::to_string(rand() * rand())};
            auto sign_index = static_cast<uint32_t>(rng() % cabinet_size);
 //           Signature signature = Sign(group_public_key.aggregate_public_key, message, private_keys[sign_index], generator_g2);
 //           Proof pi = Prove(group_public_key.public_verify_key_list[sign_index], group_public_key.aggregate_public_key, message, signature, private_keys[sign_index]);

            std::pair<Signature, Proof> sigma = SignProve(group_public_key.public_verify_key_list[sign_index], group_public_key.aggregate_public_key, message, private_keys[sign_index]);

            state.ResumeTiming();
            Verify(group_public_key.public_verify_key_list[sign_index], group_public_key.aggregate_public_key, message, sigma.first, sigma.second);

        }
    }




    void RSMS_Verify_Slow(benchmark::State &state)
    {
        details::MCLInitialiser();
        GeneratorG2 generator_g2;
        SetGenerator(generator_g2);

        // Create keys
        auto                   cabinet_size = static_cast<uint32_t>(state.range(0));

        std::vector<PublicVerifyKey>      public_verify_keys;
        std::vector<PrivateKey>           private_keys;
        GroupPublicKey                    group_public_key;

        private_keys.resize(cabinet_size);
        public_verify_keys.resize(cabinet_size);

        for (uint32_t i = 0; i < cabinet_size; ++i)
        {
            auto new_keys                         = GenerateKeyPair(generator_g2);
            private_keys[i] = new_keys.first;
            public_verify_keys[i] = new_keys.second;
        }

        group_public_key.GroupSet(public_verify_keys, generator_g2);

        for (auto _ : state)
        {
            state.PauseTiming();
            std::string message{"hello" + std::to_string(rand() * rand())};
            auto sign_index = static_cast<uint32_t>(rng() % cabinet_size);
            Signature signature = Sign(group_public_key.aggregate_public_key, message, private_keys[sign_index]);

            state.ResumeTiming();
            VerifySlow(group_public_key.public_verify_key_list[sign_index].public_key, group_public_key.aggregate_public_key, message, signature, generator_g2);

        }
    }



    void RSMS_Combine(benchmark::State &state)
    {
        details::MCLInitialiser();
        GeneratorG2 generator_g2;
        SetGenerator(generator_g2);


        auto                   cabinet_size = static_cast<uint32_t>(state.range(0));

        // Create keys
        std::vector<PublicVerifyKey>      public_verify_keys;
        std::vector<PrivateKey>           private_keys;
        GroupPublicKey                    group_public_key;

        private_keys.resize(cabinet_size);
        public_verify_keys.resize(cabinet_size);

        for (uint32_t i = 0; i < cabinet_size; ++i)
        {
            auto new_keys                         = GenerateKeyPair(generator_g2);
            private_keys[i] = new_keys.first;
            public_verify_keys[i] = new_keys.second;
        }

        group_public_key.GroupSet(public_verify_keys, generator_g2);

        for (auto _ : state)
        {
            state.PauseTiming();
            std::string message{"hello" + std::to_string(rand() * rand())};
            std::unordered_map<uint32_t, Signature> signatures;
            std::unordered_map<uint32_t, Proof> proofs;
            for (uint32_t i = 0; i < cabinet_size; ++i) {
                std::pair<Signature, Proof> sigma = SignProve(group_public_key.public_verify_key_list[i], group_public_key.aggregate_public_key, message, private_keys[i]);

                signatures.insert({i, sigma.first});
                proofs.insert({i,sigma.second});
            }


            std::unordered_map<uint32_t, Signature> validSignatures;
            state.ResumeTiming();
            for (auto const &sig : signatures){
              bool b = Verify(group_public_key.public_verify_key_list[sig.first], group_public_key.aggregate_public_key, message, sig.second, proofs[sig.first]);
              if (b) {
                  validSignatures.insert(sig);
              }
            }
            auto multi_signature = MultiSig(signatures, cabinet_size);
        }
    }


    void RSMS_Combine_Slow(benchmark::State &state)
    {
        details::MCLInitialiser();
        GeneratorG2 generator_g2;
        SetGenerator(generator_g2);

        auto                   cabinet_size = static_cast<uint32_t>(state.range(0));

        // Create keys
         std::vector<PublicVerifyKey>      public_verify_keys;
        std::vector<PrivateKey>           private_keys;
        GroupPublicKey                    group_public_key;

        private_keys.resize(cabinet_size);
        public_verify_keys.resize(cabinet_size);

        for (uint32_t i = 0; i < cabinet_size; ++i)
        {
            auto new_keys   = GenerateKeyPair(generator_g2);
            private_keys[i] = new_keys.first;
            public_verify_keys[i] = new_keys.second;
        }

        group_public_key.GroupSet(public_verify_keys, generator_g2);

        for (auto _ : state)
        {
            state.PauseTiming();
            std::string message{"hello" + std::to_string(rand() * rand())};
            std::unordered_map<uint32_t, Signature> signatures;
             for (uint32_t i = 0; i < cabinet_size; ++i) {
                Signature signature = Sign(group_public_key.aggregate_public_key, message, private_keys[i]);
                signatures.insert({i, signature});
            }


            std::unordered_map<uint32_t, Signature> validSignatures;
            state.ResumeTiming();
            for (auto const &sig : signatures){
                bool b = VerifySlow(group_public_key.public_verify_key_list[sig.first].public_key, group_public_key.aggregate_public_key, message, sig.second, generator_g2);
                if (b) {
                    validSignatures.insert(sig);
                }
            }
            auto multi_signature = MultiSig(signatures, cabinet_size);
        }
    }


/*
    void RSMS_VerifyMulti(benchmark::State &state)
    {
        details::MCLInitialiser();
        GeneratorG2 generator_g2;
        SetGenerator(generator_g2);


        auto                   cabinet_size = static_cast<uint32_t>(state.range(0));

        // Create keys
        std::vector<PublicVerifyKey>      public_verify_keys;
        std::vector<PrivateKey>           private_keys;
        GroupPublicKey                    group_public_key;

        private_keys.resize(cabinet_size);
        public_verify_keys.resize(cabinet_size);

        for (uint32_t i = 0; i < cabinet_size; ++i)
        {
            auto new_keys                         = GenerateKeyPair(generator_g2);
            private_keys[i] = new_keys.first;
            public_verify_keys[i] = new_keys.second;
        }

        group_public_key.GroupSet(public_verify_keys, generator_g2);

        for (auto _ : state)
        {
            state.PauseTiming();
            std::string message{"hello" + std::to_string(rand() * rand())};

            std::unordered_map<uint32_t, Signature> validSignatures;
            for (uint32_t i = 0; i < cabinet_size; ++i) {
                std::pair<Signature, Proof> sigma = SignProve(group_public_key.public_verify_key_list[i], group_public_key.aggregate_public_key, message, private_keys[i]);
                bool b = Verify(group_public_key.public_verify_key_list[i], group_public_key.aggregate_public_key, message, sigma.first, sigma.second);
                if (b) {
                    validSignatures.insert({i, sigma.first});
                }
            }

            auto multi_signature = MultiSig(validSignatures, cabinet_size);
            state.ResumeTiming();
            VerifyMulti(message, multi_signature, group_public_key, generator_g2);
        }
    }
*/

}  // namespace

BENCHMARK(RSMS_SignProve)->RangeMultiplier(2)->Range(50, 500);
BENCHMARK(RSMS_Verify)->RangeMultiplier(2)->Range(50, 500);
BENCHMARK(RSMS_Verify_Slow)->RangeMultiplier(2)->Range(50, 500);
BENCHMARK(RSMS_Combine)->RangeMultiplier(2)->Range(50, 500);
BENCHMARK(RSMS_Combine_Slow)->RangeMultiplier(2)->Range(50, 500);
//BENCHMARK(RSMS_VerifyMulti)->RangeMultiplier(2)->Range(50, 500);