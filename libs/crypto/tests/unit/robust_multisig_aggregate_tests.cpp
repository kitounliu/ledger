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

#include "crypto/robust_multisig_aggregate.hpp"

#include "gtest/gtest.h"

#include <cstdint>
#include <iostream>
#include <ostream>

using namespace fetch::crypto::arms::mcl;
using namespace fetch::byte_array;


TEST(MclMultiSigAggTests, RobustAggSignVerify)
{
  details::MCLInitialiser();

  GeneratorG2 generator_g2;
  SetGenerator(generator_g2);

  uint32_t                          transaction_size = 8;
  uint32_t                          wallet_size = 5;

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

  std::vector<MessagePayload>                          messages;
  messages.resize(transaction_size);
  for (uint32_t i = 0; i<transaction_size; i++){
      messages[i] = "transaction" + std::to_string(rand() * rand());
  }

  std::vector<Signature> signatures;
  for (uint32_t i = 0; i < transaction_size; i++)
  {
      Signature sig = Sign(messages[i], SK[i], PK[i], generator_g2);

      EXPECT_TRUE(VerifySlow(PK[i], messages[i], sig, generator_g2));

      std::pair<Signature, Proof> sigma = SignProve(messages[i], SK[i], PK[i], generator_g2);

      EXPECT_TRUE(VerifySlow(PK[i], messages[i], sigma.first, generator_g2));

      EXPECT_TRUE(Verify(generator_g2, PK[i], messages[i], sigma.first, sigma.second));

      signatures.push_back(sigma.first);
  }

  auto aggregate_signature = AggregateSig(signatures);

  EXPECT_TRUE(VerifyAggSig(messages, aggregate_signature, PK, generator_g2));

}



TEST(MclOperationTests, PairingTest){
    details::MCLInitialiser();

    GeneratorG1 g("hello"), h("world"), gh, g2x;

    bn::G1::add(gh, g, h);

    GeneratorG2 g2;
    SetGenerator(g2);

    bn::Fp12 eg, eh, egh, eadd, eg2x, et;

    bn::pairing(eg, g, g2);
    bn::pairing(eh, h, g2);
    bn::GT::mul(eadd, eg, eh);

    bn::pairing(egh, gh, g2);

    EXPECT_TRUE(eadd == egh);

    PrivateKey x;
    x.setRand();

    bn::G1::mul(g2x, g, x);
    bn::pairing(eg2x, g2x, g2);
    bn::GT::pow(et, eg, x);

    EXPECT_TRUE(eg2x == et);
}