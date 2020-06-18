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
#include "crypto/multisig_rsmspop.hpp"

#include "benchmark/benchmark.h"

using fetch::byte_array::ByteArray;
using fetch::byte_array::ConstByteArray;


using namespace fetch::crypto::rsmspop::mcl;

using RNG = fetch::random::LinearCongruentialGenerator;

namespace {

RNG rng;



    void RSMSPOP_Sign(benchmark::State &state)
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
            auto new_keys                         = GenerateKeys(generator_g2);
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
        Sign(message, private_keys[sign_index], group_public_key.tag);


        }
    }


void RSMSPOP_SignProve(benchmark::State &state)
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
        auto new_keys                         = GenerateKeys(generator_g2);
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

    SignProve(message, private_keys[sign_index], group_public_key.tag, group_public_key.public_verify_keys[sign_index]);

  }
}



void RSMSPOP_Verify(benchmark::State &state)
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
            auto new_keys                         = GenerateKeys(generator_g2);
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

            std::pair<Signature, Proof> sigma = SignProve(message, private_keys[sign_index], group_public_key.tag, group_public_key.public_verify_keys[sign_index]);

            state.ResumeTiming();
            Verify(message, sigma.first, sigma.second, group_public_key.tag, group_public_key.public_verify_keys[sign_index]);

        }
    }




    void RSMSPOP_Verify_Slow(benchmark::State &state)
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
            auto new_keys                         = GenerateKeys(generator_g2);
            private_keys[i] = new_keys.first;
            public_verify_keys[i] = new_keys.second;
        }

        group_public_key.GroupSet(public_verify_keys, generator_g2);

        for (auto _ : state)
        {
            state.PauseTiming();
            std::string message{"hello" + std::to_string(rand() * rand())};
            auto sign_index = static_cast<uint32_t>(rng() % cabinet_size);
            Signature signature = Sign(message, private_keys[sign_index], group_public_key.tag);

            state.ResumeTiming();
            VerifySlow(message, signature, group_public_key.tag, group_public_key.public_verify_keys[sign_index].public_key, generator_g2);

        }
    }



    void RSMSPOP_Combine(benchmark::State &state)
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
            auto new_keys                         = GenerateKeys(generator_g2);
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
                std::pair<Signature, Proof> sigma = SignProve(message, private_keys[i],  group_public_key.tag, group_public_key.public_verify_keys[i]);

                signatures.insert({i, sigma.first});
                proofs.insert({i,sigma.second});
            }


            std::unordered_map<uint32_t, Signature> validSignatures;
            state.ResumeTiming();
            for (auto const &sig : signatures){
              bool b = Verify(message, sig.second, proofs[sig.first],  group_public_key.tag, group_public_key.public_verify_keys[sig.first]);
              if (b) {
                  validSignatures.insert(sig);
              }
            }
            auto multi_signature = MultiSig(signatures, cabinet_size);
        }
    }


    void RSMSPOP_Combine_Slow(benchmark::State &state)
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
            auto new_keys   = GenerateKeys(generator_g2);
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
                Signature signature = Sign(message, private_keys[i], group_public_key.tag);
                signatures.insert({i, signature});
            }


            std::unordered_map<uint32_t, Signature> validSignatures;
            state.ResumeTiming();
            for (auto const &sig : signatures){
                bool b = VerifySlow( message, sig.second, group_public_key.tag, group_public_key.public_verify_keys[sig.first].public_key,  generator_g2);
                if (b) {
                    validSignatures.insert(sig);
                }
            }
            auto multi_signature = MultiSig(signatures, cabinet_size);
        }
    }



    void RSMSPOP_VerifyMulti(benchmark::State &state)
    {
        details::MCLInitialiser();
        GeneratorG2 generator_g2;
        SetGenerator(generator_g2);


        auto                   cabinet_size = static_cast<uint32_t>(state.range(0));

        // Create keys
        std::vector<PublicVerifyKey>      public_verify_keys;
        std::vector<PrivateKey>           private_keys;
        GroupPublicKey                    group_public_key;
        PrivateKey fast_key; // for fast signature

        private_keys.resize(cabinet_size);
        public_verify_keys.resize(cabinet_size);

        SignerRecord signers;
        signers.resize(cabinet_size, 0);

        for (uint32_t i = 0; i < cabinet_size; ++i)
        {
            auto new_keys                         = GenerateKeys(generator_g2);
            private_keys[i] = new_keys.first;
            public_verify_keys[i] = new_keys.second;

            // for simulating fast multi-signature
            bn::Fr::add(fast_key, fast_key, private_keys[i]);
            signers[i] = 1;
        }

        group_public_key.GroupSet(public_verify_keys, generator_g2);

        for (auto _ : state)
        {
            state.PauseTiming();
            std::string message{"hello" + std::to_string(rand() * rand())};

            Signature aggregate_signature = Sign(message, fast_key, group_public_key.tag);

            MultiSignature sigma = std::make_pair(aggregate_signature, signers);

            state.ResumeTiming();
            VerifyMulti(message, sigma, group_public_key, generator_g2);
        }
    }


    constexpr uint32_t cabinet_size = 100;

    void RSMSPOP_Aggregate(benchmark::State &state)
    {
      details::MCLInitialiser();
      GeneratorG2 generator_g2;
      SetGenerator(generator_g2);

      // Create keys
      //uint32_t                  cabinet_size = 200;
      uint32_t block_height = static_cast<uint32_t>(state.range(0));


      std::vector<std::vector<PrivateKey>>           SK;
      std::vector<std::vector<PublicVerifyKey>>            PVK;
      std::vector<GroupPublicKey>                   GPK;
      std::vector<PrivateKey>                 fast_keys;
      std::vector<SignerRecord>                 signers;



      SK.resize(block_height);
      PVK.resize(block_height);
      GPK.resize(block_height);
      fast_keys.resize(block_height);
      signers.resize(block_height);


      for (uint32_t i = 0; i< block_height; i++)
      {
        SK[i].resize(cabinet_size);
        PVK[i].resize(cabinet_size);
        signers[i].resize(cabinet_size);
      }

      for (uint32_t i = 0; i < block_height; i++)
      {
        for (uint32_t j = 0; j < cabinet_size; j++)
        {
          auto new_keys                         = GenerateKeys(generator_g2);
          SK[i][j] = new_keys.first;
          PVK[i][j] = new_keys.second;

          bn::Fr::add(fast_keys[i], fast_keys[i], SK[i][j]);

          signers[i][j] = 1;

        }
        GPK[i].GroupSet(PVK[i], generator_g2);

      }



      std::vector<MessagePayload>              messages;
      messages.resize(block_height);
      for (uint32_t i = 0; i<block_height; i++){
        messages[i] = "block header: " + std::to_string(rand());
      }


      for (auto _ : state)
      {
        state.PauseTiming();

        std::vector<MultiSignature>                sigmas;
        sigmas.resize(block_height);
        for (uint32_t i = 0; i < block_height; ++i) {
          Signature sig = Sign(messages[i], fast_keys[i], GPK[i].tag);
          sigmas[i] = std::make_pair(sig, signers[i]);
        }

        std::vector<MultiSignature> validSignatures;
        state.ResumeTiming();
        for (uint32_t i = 0; i < block_height; ++i){
          bool b = VerifyMulti(messages[i], sigmas[i], GPK[i], generator_g2);
          if (b) {
            validSignatures.push_back(sigmas[i]);
          }
        }
        AggregateSig(validSignatures);
      }
    }



    void RSMSPOP_VerifyAgg(benchmark::State &state)
    {
      details::MCLInitialiser();
      GeneratorG2 generator_g2;
      SetGenerator(generator_g2);

      // Create keys
      //uint32_t                  cabinet_size = 100;
      uint32_t block_height = static_cast<uint32_t>(state.range(0));


      std::vector<std::vector<PrivateKey>>           SK;
      std::vector<std::vector<PublicVerifyKey>>     PVK;
      std::vector<GroupPublicKey>                   GPK;
      std::vector<PrivateKey>                 fast_keys;
      std::vector<SignerRecord>                 signers;


      SK.resize(block_height);
      PVK.resize(block_height);
      GPK.resize(block_height);
      fast_keys.resize(block_height);
      signers.resize(block_height);


      for (uint32_t i = 0; i< block_height; i++)
      {
        SK[i].resize(cabinet_size);
        PVK[i].resize(cabinet_size);
        signers[i].resize(cabinet_size);
      }

      for (uint32_t i = 0; i < block_height; i++)
      {
        for (uint32_t j = 0; j < cabinet_size; j++)
        {
          auto new_keys                         = GenerateKeys(generator_g2);
          SK[i][j] = new_keys.first;
          PVK[i][j] = new_keys.second;

          bn::Fr::add(fast_keys[i], fast_keys[i], SK[i][j]);

          signers[i][j] = 1;
        }
        GPK[i].GroupSet(PVK[i], generator_g2);

      }



      std::vector<MessagePayload>              messages;
      messages.resize(block_height);
      for (uint32_t i = 0; i<block_height; i++){
        messages[i] = "block header: " + std::to_string(rand());
      }


      for (auto _ : state)
      {
        state.PauseTiming();

        std::vector<MultiSignature>                sigmas;
        sigmas.resize(block_height);
        for (uint32_t i = 0; i < block_height; ++i) {
          Signature sig = Sign(messages[i], fast_keys[i], GPK[i].tag);
          sigmas[i] = std::make_pair(sig, signers[i]);
        }


        auto aggregate_signature = AggregateSig(sigmas);

        state.ResumeTiming();
        VerifyAgg(messages, aggregate_signature, GPK, generator_g2);
      }
    }



}  // namespace

BENCHMARK(RSMSPOP_Sign)->RangeMultiplier(2)->Range(50, 500);
BENCHMARK(RSMSPOP_SignProve)->RangeMultiplier(2)->Range(50, 500);
BENCHMARK(RSMSPOP_Verify)->RangeMultiplier(2)->Range(50, 500);
BENCHMARK(RSMSPOP_Verify_Slow)->RangeMultiplier(2)->Range(50, 500);
BENCHMARK(RSMSPOP_Combine)->RangeMultiplier(2)->Range(50, 500);
BENCHMARK(RSMSPOP_Combine_Slow)->RangeMultiplier(2)->Range(50, 500);
BENCHMARK(RSMSPOP_VerifyMulti)->RangeMultiplier(2)->Range(50, 500);
BENCHMARK(RSMSPOP_Aggregate)->RangeMultiplier(2)->Range(50, 500);
BENCHMARK(RSMSPOP_VerifyAgg)->RangeMultiplier(2)->Range(50, 500);