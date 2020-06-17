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

#include "crypto/multisig_rsmsp.hpp"

#include <cassert>
#include <cstddef>
#include <stdexcept>
#include <unordered_map>

namespace fetch {
namespace crypto {
namespace rsmsp {
namespace mcl {

std::atomic<bool>  details::MCLInitialiser::was_initialised{false};
constexpr uint16_t PUBLIC_KEY_BYTE_SIZE = 310;

    GeneratorG1::GeneratorG1()
    {
      clear();
    }


    GeneratorG1::GeneratorG1(std::string const &string_to_hash)
    {
      clear();
      bn::hashAndMapToG1(*this, string_to_hash);
    }


    GeneratorG2::GeneratorG2()
    {
        clear();
    }


    GeneratorG2::GeneratorG2(std::string const &string_to_hash)
    {
        clear();
        bn::hashAndMapToG2(*this, string_to_hash);
    }


    PublicKey::PublicKey()
    {
        clear();
    }


    PrivateKey::PrivateKey()
    {
        clear();
    }


    void PrivateKey::setHash(GeneratorG1 const &generator_g1, Signature const & Hmess, PublicKey const &public_key, Signature const &sig, PublicKey const &com1, Signature const &com2)
    {
      std::ostringstream os;
      os << generator_g1 << Hmess << public_key << sig << com1 << com2;
      bn::Fr::setHashOf(os.str());
    }

    GroupTag::GroupTag() {
        clear();
    }



    Signature::Signature()
    {
        clear();
    }


    /* todo: implement toString and assign for all classes
    std::pair<std::string, std::string> Proof::toString() const {
        return std::make_pair(first.getStr(), second.getStr());
    }

    bool Proof::assign(const std::pair<std::string, std::string> &s) {
          return first.assign(s.first) && second.assign(s.second);
    }
*/



    /**
 * Generates a private key and the corresponding public key
 *
 * @param generator Choice of generator on the elliptic curve
 * @return Pair of private and public keys
 */
    std::pair<PrivateKey, PublicKey> GenerateKeys(GeneratorG1 const &generator_g1)
    {
        std::pair<PrivateKey, PublicKey> key_pair;
        key_pair.first.setRand();
        bn::G1::mul(key_pair.second, generator_g1, key_pair.first);

        return key_pair;
    }


    void SetGenerator(GeneratorG1 &generator_g1, std::string const &string_to_hash)
    {
      assert(!string_to_hash.empty());
      bn::hashAndMapToG1(generator_g1, string_to_hash);
      assert(!generator_g1.isZero());
    }


    void SetGenerator(GeneratorG2 &generator_g2, std::string const &string_to_hash)
    {
        assert(!string_to_hash.empty());
        bn::hashAndMapToG2(generator_g2, string_to_hash);
        assert(!generator_g2.isZero());
    }


     bool GroupPublicKey::GroupSet(std::vector<PublicKey> const &public_key_list){

       if (public_key_list.size()==0) {
         return false;
       }

       const std::string hash_function_reuse_appender =
           "MultiSig-RSMSP-00000000000000000000000000000000";

       std::string concatenated_public_keys;
       concatenated_public_keys.reserve(hash_function_reuse_appender.length() +
                                        (public_key_list.size() + 1) * PUBLIC_KEY_BYTE_SIZE);

       concatenated_public_keys += hash_function_reuse_appender;

       for (auto const &key : public_key_list)
       {
         concatenated_public_keys += key.getStr();
       }

       tag.setHashOf(concatenated_public_keys);

       public_keys.insert(public_keys.end(), public_key_list.begin(), public_key_list.end());

       return true;
    }



    Signature Sign(MessagePayload const &message, PrivateKey const &sk, GroupTag const &group_tag)
    {
        std::string gtag_mess = group_tag.getStr() + message;

        Signature Hmess;
        Signature sig;
        bn::hashAndMapToG2(Hmess, gtag_mess);

        bn::G2::mul(sig, Hmess, sk);  // sign = s H(gtag, m)

        return sig;
    }




// sign a message and generate a NIZK proof
        std::pair<Signature, Proof> SignProve(MessagePayload const &message, PrivateKey const &sk, GroupTag const &group_tag, const PublicKey &public_key, GeneratorG1 const &generator_g1)
        {
          std::string gtag_mess = group_tag.getStr() + message;

          Signature Hmess;
          Signature sig;
          bn::hashAndMapToG2(Hmess, gtag_mess);

          bn::G2::mul(sig, Hmess, sk);  // sign = s H(gtag, m)

          PrivateKey r;
          r.setRand();

          PublicKey com1;
          bn::G1::mul(com1, generator_g1, r);

          Signature com2;
          bn::G2::mul(com2, Hmess, r);

          Proof pi;
          pi.first.setHash(generator_g1, Hmess, public_key, sig, com1, com2);
          PrivateKey localVar;
          bn::Fr::mul(localVar, pi.first, sk);
          bn::Fr::add(pi.second, localVar, r);

          return std::make_pair(sig,pi);
        }




// verify a signature with a NIZK proof (sig, pi)
        bool Verify(const MessagePayload &message, const Signature &sig, const Proof &pi, GroupTag const &group_tag,  PublicKey const &public_key,   GeneratorG1 const &generator_g1) {
            std::string gtag_mess = group_tag.getStr() + message;

            Signature Hmess;
            bn::hashAndMapToG2(Hmess, gtag_mess);

            PublicKey com1, tmp1, tmp2;
            Signature com2, tmp3, tmp4;

            bn::G1::mul(tmp1, generator_g1, pi.second);
            bn::G1::mul(tmp2, public_key, pi.first);
            bn::G1::sub(com1, tmp1, tmp2);


            bn::G2::mul(tmp3, Hmess, pi.second);
            bn::G2::mul(tmp4, sig, pi.first);
            bn::G2::sub(com2, tmp3, tmp4);

            PrivateKey ch;
            ch.setHash(generator_g1, Hmess, public_key, sig, com1, com2);

            return pi.first == ch;
        }


/**
 * Verifies a signature by pairing equation
 *
 * @param y The public key (can be the group public key, or public key share)
 * @param message Message that was signed
 * @param sign Signature to be verified
 * @param G Generator used in DKG
 * @return
 */
        bool VerifySlow(MessagePayload const &message, Signature const &sig, GroupTag const &group_tag, PublicKey const &pk,
                        GeneratorG1 const &generator_g1)
        {
            std::string gtag_mess = group_tag.getStr() + message;

            Signature Hmess;
            bn::hashAndMapToG2(Hmess, gtag_mess);

            bn::Fp12  e1, e2;

            bn::pairing(e1, generator_g1, sig);
            bn::pairing(e2, pk, Hmess);

            return e1 == e2;
        }



Coefficients AggregateCoefficients(GroupPublicKey const &gpk, SignerRecord signers)
      {
        assert(signers.size() == gpk.public_keys.size());

        Coefficients coefficients;

        // Reserve first 48 bytes for some fixed value as the hash function (also used in DKG) is being
        // reused here in different contexts
        const std::string hash_function_reuse_appender =
            "MultiSig RSMSP Coefficients 00000000000000000000000000000000";

        std::string concatenated_gtag_signers;

        concatenated_gtag_signers = hash_function_reuse_appender + gpk.tag.getStr();


        for (uint32_t i = 0; i < signers.size(); i++)
        {
          if (signers[i] == 1){
            concatenated_gtag_signers = concatenated_gtag_signers + " " + std::to_string(i);
          }
        }


        for (uint32_t i = 0; i < signers.size(); i++){
          if (signers[i] == 1)
          {
            PrivateKey  coefficient;
            std::string keyString = gpk.public_keys[i].getStr() + concatenated_gtag_signers;
            coefficient.setHashOf(keyString);
            coefficients.insert({i, coefficient});
          }
        }

        return coefficients;
      }


// multi-signature = s_1^{a_1}...s_n^{a_n}
        MultiSignature MultiSig(std::unordered_map<uint32_t, Signature> const &signatures, uint32_t cabinet_size, GroupPublicKey const &gpk)
        {
            Signature    multi_signature;
            SignerRecord signers;
            signers.resize(cabinet_size, 0);

            // Add individual signatures to compute aggregate signature

          for (auto const &sig : signatures)
          {
            signers[sig.first] = 1;
          }

          Coefficients coefficients  = AggregateCoefficients(gpk, signers);

          for (auto const &sig : signatures)
          {
              Signature tmp;
              bn::G2::mul(tmp, sig.second, coefficients[sig.first]);
              bn::G2::add(multi_signature, multi_signature, tmp);
          }
          return std::make_pair(multi_signature, signers);
        }



        PublicKey AggregatePublicKey(GroupPublicKey const &gpk, SignerRecord signers)
        {
          PublicKey aggregate_public_key;
          Coefficients coefficients = AggregateCoefficients(gpk, signers);

          for(uint32_t i = 0; i < signers.size(); i++){
            if (signers[i] == 1){
              PublicKey tpk;
              bn::G1::mul(tpk, gpk.public_keys[i], coefficients[i]);
              bn::G1::add(aggregate_public_key, aggregate_public_key, tpk);
            }
          }

          return aggregate_public_key;
        }



        bool VerifyMulti(MessagePayload const &message, MultiSignature const &sigma, GroupPublicKey const &gpk, GeneratorG1 const &generator_g1)
        {
            PublicKey apk = AggregatePublicKey(gpk, sigma.second);
            if (apk.isZero()) {
                return false;
            }

            std::string gtag_mess = gpk.tag.getStr() + message;
            Signature Hmess;
            bn::hashAndMapToG2(Hmess, gtag_mess);

            bn::Fp12  e1, e2;

            bn::pairing(e1, generator_g1, sigma.first);
            bn::pairing(e2, apk, Hmess);

            return e1 == e2;
        }



// aggregate_signature = multi_sig_1 multi_sig_2 ... multi_sig_k
        AggSignature AggregateSig(std::vector<MultiSignature> const &multi_signatures)
        {
          AggSignature aggregate_signature;

          for (auto const &msig : multi_signatures)
          {
            bn::G2::add(aggregate_signature.first, aggregate_signature.first, msig.first);
            aggregate_signature.second.push_back(msig.second);
          }
          return aggregate_signature;
        }


        bool VerifyAgg(std::vector<MessagePayload> const & messages, AggSignature const &aggregate_signature, std::vector<GroupPublicKey> const &gpks, GeneratorG1 const &generator_g1)
        {
          assert(messages.size() == gpks.size() && gpks.size() == aggregate_signature.second.size());

          std::vector<PublicKey> apks;
          apks.resize(gpks.size());
          for (uint32_t i = 0; i < gpks.size(); i++){
            apks[i] = AggregatePublicKey(gpks[i], aggregate_signature.second[i]);
          }

          bn::Fp12  e1, e2;
          e2.setOne();


          bn::pairing(e1, generator_g1, aggregate_signature.first);

          for (uint32_t i = 0; i < gpks.size(); i++){
            std::string gtag_mess = gpks[i].tag.getStr() + messages[i];
            Signature Hmess;
            bn::hashAndMapToG2(Hmess, gtag_mess);

            bn::Fp12  tmp;
            bn::pairing(tmp, apks[i], Hmess);

            bn::GT::mul(e2, e2, tmp);

          }

          return e1 == e2;
        }

    }  // namespace mcl
}  // namespace rsmsp
}  // namespace crypto
}  // namespace fetch
