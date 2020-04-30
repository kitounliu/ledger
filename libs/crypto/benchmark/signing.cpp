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
#include "core/byte_array/const_byte_array.hpp"
#include "core/random/lcg.hpp"
#include "crypto/ecdsa.hpp"

#include "benchmark/benchmark.h"

#include <stdexcept>

using fetch::byte_array::ByteArray;
using fetch::byte_array::ConstByteArray;
using fetch::crypto::ECDSASigner;
using fetch::crypto::ECDSAVerifier;
using fetch::random::LinearCongruentialGenerator;

namespace {

using RNG = LinearCongruentialGenerator;

RNG rng;

template <std::size_t LENGTH>
ConstByteArray GenerateRandomData()
{
  static constexpr std::size_t RNG_WORD_SIZE = sizeof(RNG::RandomType);
  static constexpr std::size_t NUM_WORDS     = LENGTH / RNG_WORD_SIZE;

  static_assert((LENGTH % RNG_WORD_SIZE) == 0, "Size must be a multiple of random type");

  ByteArray buffer;
  buffer.Resize(LENGTH);

  auto *words = reinterpret_cast<RNG::RandomType *>(buffer.pointer());
  for (std::size_t i = 0; i < NUM_WORDS; ++i)
  {
    *words++ = rng();
  }

  return ConstByteArray{buffer};
}


    void ECDSA_Sign(benchmark::State &state)
    {
        auto                      wallet_size = static_cast<uint32_t>(state.range(0));


        for (auto _ : state)
        {
            state.PauseTiming();
            // create the signer
            ECDSASigner signer;
            ConstByteArray msg = GenerateRandomData<2048>();

            state.ResumeTiming();
            for (uint32_t j = 0; j < wallet_size; j++) {
                // generate a random message

                // create the signed data
                signer.Sign(msg);
            }
        }
    }



void ECDSA_Verify(benchmark::State &state)
{
    auto                      wallet_size = static_cast<uint32_t>(state.range(0));




    for (auto _ : state)
    {
        state.PauseTiming();
        // create the signer
        ECDSASigner signer;
        ECDSAVerifier verifier(signer.identity());

        // generate a random message
        ConstByteArray msg = GenerateRandomData<2048>();

        std::vector<ConstByteArray> sigma;
        for (uint32_t j = 0; j < wallet_size; j++) {

            // create the signed data
            auto const signature = signer.Sign(msg);
            if (signature.empty())
            {
                throw std::runtime_error("Unable to sign the message");
            }
            sigma.push_back(signature);
        }


        state.ResumeTiming();

        for (auto sig: sigma) {
            verifier.Verify(msg, sig);
        }
    }

}





}  // namespace



BENCHMARK(ECDSA_Sign)->RangeMultiplier(2)->Range(1, 1<<12);
BENCHMARK(ECDSA_Verify)->RangeMultiplier(2)->Range(1, 1<<12);