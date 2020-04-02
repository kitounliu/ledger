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

#include "crypto/aggregating_multisig.hpp"

#include "gtest/gtest.h"

#include <cstdint>
#include <iostream>
#include <ostream>

using namespace fetch::crypto::amsp::mcl;
using namespace fetch::byte_array;


TEST(MclAggMultiSigTests, AggregatingSignVerify)
{
  details::MCLInitialiser();

  GeneratorG2 generator_g2;
  SetGenerator(generator_g2);

  uint32_t                          transaction_size = 1;
  uint32_t                          wallet_size = 2;

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

  std::vector<Signature> multiSignatures;
  for (uint32_t i = 0; i < transaction_size; i++)
  {
      std::vector<PrivateKey> coefficients = AggregateCoefficients(PK[i]);
      PublicKey aggregate_public_key = AggregatePublicKey(PK[i], coefficients);


      std::vector<Signature> signatures;
      for (uint32_t j = 0; j < wallet_size; j++){
          Signature sig = Sign(messages[i], SK[i][j], coefficients[j], aggregate_public_key);
          signatures.push_back(sig);
      }

      Signature sigma = MultiSig(signatures);
      EXPECT_TRUE(VerifyMulti(PK[i], messages[i], sigma, generator_g2));
      multiSignatures.push_back(sigma);
  }

  auto aggregate_signature = AggregateSig(multiSignatures);

  EXPECT_TRUE(VerifyAgg(messages, aggregate_signature, PK, generator_g2));


}


