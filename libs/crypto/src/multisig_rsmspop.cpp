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

#include "crypto/multisig_rsmspop.hpp"

#include <cassert>
#include <cstddef>
#include <stdexcept>
#include <unordered_map>

namespace fetch {
namespace crypto {
namespace rsmspop {
namespace mcl {

std::atomic<bool>  details::MCLInitialiser::was_initialised{false};
constexpr uint16_t PUBLIC_KEY_BYTE_SIZE = 310;



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


    VerifyKey::VerifyKey()
    {
        clear();
    }

    PrivateKey::PrivateKey()
    {
        clear();
    }

    void PrivateKey::setHash(VerifyKey const &Hpk, Signature const & Hmess, VerifyKey const &verify_key, Signature const &sig, VerifyKey const &com1, VerifyKey const &com2)
    {
        std::ostringstream os;
        os << Hpk << Hmess << verify_key << sig << com1 << com2;
        bn::Fr::setHashOf(os.str());
    }


//    PrivateKey::PrivateKey(uint32_t value)
//    {
//        clear();
//        bn::Fr::add(*this, *this, value);
//    }


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
    std::pair<PrivateKey, PublicVerifyKey> GenerateKeys(GeneratorG2 const &generator_g2)
    {
        std::pair<PrivateKey, PublicVerifyKey> key_pair;
        key_pair.first.setRand();
        bn::G2::mul(key_pair.second.public_key, generator_g2, key_pair.first);

        VerifyKey hash_public_key;

        bn::hashAndMapToG1(hash_public_key, key_pair.second.public_key.getStr());
        bn::G1::mul(key_pair.second.verify_key, hash_public_key, key_pair.first);
        return key_pair;
    }


    bool PublicVerifyKey::Validate(GeneratorG2 const &generator_g2) const {
        bn::G1 hash;
        bn::hashAndMapToG1(hash, public_key.getStr());

        bn::Fp12  e1, e2;
        bn::pairing(e1, verify_key, generator_g2);
        bn::pairing(e2, hash, public_key);
        return e1==e2;
    }





    void SetGenerator(GeneratorG2 &generator_g2, std::string const &string_to_hash)
    {
        assert(!string_to_hash.empty());
        bn::hashAndMapToG2(generator_g2, string_to_hash);
        assert(!generator_g2.isZero());
    }


     bool GroupPublicKey::GroupSet(std::vector<PublicVerifyKey> const &public_verify_key_list, GeneratorG2 const &generator_g2){

         for (const auto & public_verify_key : public_verify_key_list){
             if (!public_verify_key.Validate(generator_g2)) return false;
         }

         const std::string hash_function_reuse_appender =
             "MultiSig-RSMSPOP-00000000000000000000000000000000";

         std::string concatenated_public_keys;
         concatenated_public_keys.reserve(hash_function_reuse_appender.length() +
                                          (public_verify_key_list.size() + 1) * PUBLIC_KEY_BYTE_SIZE);

         concatenated_public_keys += hash_function_reuse_appender;

         for (auto const &key : public_verify_key_list)
         {
           concatenated_public_keys += key.public_key.getStr();
         }
         tag.setHashOf(concatenated_public_keys);

         public_verify_keys.insert(public_verify_keys.end(), public_verify_key_list.begin(),public_verify_key_list.end());

         return true;
    }


    /**
 * Computes signature share of a message
 *
 * @param message Message to be signed
 * @param x_i Secret key share
 * @return Signature share
 */
    Signature Sign(MessagePayload const &message, PrivateKey const &sk, GroupTag const &group_tag)
    {
        std::string gtag_mess = group_tag.getStr() + message;

        Signature Hmess;
        Signature sig;
        bn::hashAndMapToG1(Hmess, gtag_mess);

        bn::G1::mul(sig, Hmess, sk);  // sign = s H(m)

        return sig;
    }




        std::pair<Signature, Proof> SignProve(MessagePayload const &message, PrivateKey const &sk, GroupTag const &group_tag, const PublicVerifyKey &public_verify_key)
        {
          std::string gtag_mess = group_tag.getStr() + message;

            Signature Hmess;
            Signature sig;
            bn::hashAndMapToG1(Hmess, gtag_mess);

            bn::G1::mul(sig, Hmess, sk);  // sign = s H(m)

            PrivateKey r;
            r.setRand();

            VerifyKey Hpk, com1, com2;
            bn::hashAndMapToG1(Hpk, public_verify_key.public_key.getStr());
            bn::G1::mul(com1, Hpk, r);

            bn::G1::mul(com2, Hmess, r);

            Proof pi;
            pi.first.setHash(Hpk, Hmess, public_verify_key.verify_key, sig, com1, com2);
            PrivateKey localVar;
            bn::Fr::mul(localVar, pi.first, sk);
            bn::Fr::add(pi.second, localVar, r);

            return std::make_pair(sig,pi);
        }




// verify a NIZK proof (sig, pi)
        bool Verify(MessagePayload const &message,  Signature const &sig, const Proof &pi, GroupTag const &group_tag, PublicVerifyKey const &public_verify_key) {
            std::string gtag_mess = group_tag.getStr() + message;

            Signature Hmess;
            bn::hashAndMapToG1(Hmess, gtag_mess);

            VerifyKey Hpk, com1,  com2, tmp1, tmp2;
            bn::hashAndMapToG1(Hpk, public_verify_key.public_key.getStr());

            bn::G1::mul(tmp1, Hpk, pi.second);
            bn::G1::mul(tmp2, public_verify_key.verify_key, pi.first);
            bn::G1::sub(com1, tmp1, tmp2);


            bn::G1::mul(tmp1, Hmess, pi.second);
            bn::G1::mul(tmp2, sig, pi.first);
            bn::G1::sub(com2, tmp1, tmp2);

            PrivateKey ch;
            ch.setHash(Hpk, Hmess, public_verify_key.verify_key, sig, com1, com2);

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
        bool VerifySlow(MessagePayload const &message, Signature const &sig, GroupTag const &group_tag, PublicKey const &public_key,
                        GeneratorG2 const &generator_g2)
        {
            std::string gtag_mess = group_tag.getStr() + message;

            Signature Hmess;
            bn::hashAndMapToG1(Hmess, gtag_mess);

            bn::Fp12  e1, e2;

            bn::pairing(e1, sig, generator_g2);
            bn::pairing(e2, Hmess, public_key);

            return e1 == e2;
        }



/**
 * Computes aggregate signature from signatures of a message
 *
 * @param signatures Map of the signer index and their signature of a message
 * @param cabinet_size Size of cabinet
 * @return Pair consisting of aggregate signature and a vector indicating who's signatures were
 * aggregated
 */
        MultiSignature MultiSig(std::unordered_map<uint32_t, Signature> const &signatures, uint32_t cabinet_size)
        {
            Signature    multi_signature;
            SignerRecord signers;
            signers.resize(cabinet_size, 0);

            // Add individual signatures to compute aggregate signature
            for (auto const &sig : signatures)
            {
                bn::G1::add(multi_signature, multi_signature, sig.second);
                signers[sig.first] = 1;
            }
            return std::make_pair(multi_signature, signers);
        }


        MultiSignature Compress(MultiSignature const &sigma1, MultiSignature const &sigma2, uint32_t cabinet_size)
        {
            Signature    multi_signature;
            SignerRecord signers;
            signers.resize(cabinet_size, 0);

            assert(sigma1.second.size()==cabinet_size && sigma2.second.size()==cabinet_size);
            // Add individual signatures to compute multi-signature
            for (uint32_t i=0; i<cabinet_size;i++)
            {
                assert(sigma1.second[i]==0 ||  sigma2.second[i]==0);
                if (sigma1.second[i]==1 ||  sigma2.second[i]==1)
                        signers[i] = 1;
            }

            bn::G1::add(multi_signature, sigma1.first, sigma2.first);

            return std::make_pair(multi_signature, signers);
        }


        PublicKey AggregatePublicKey(GroupPublicKey const &gpk, SignerRecord signers)
        {
          assert(signers.size() == gpk.public_verify_keys.size());

          PublicKey aggregate_public_key;

          for(uint32_t i = 0; i < signers.size(); i++){
            if (signers[i] == 1){
                 bn::G2::add(aggregate_public_key, aggregate_public_key, gpk.public_verify_keys[i].public_key);
            }
          }

          return aggregate_public_key;
        }


        bool VerifyMulti(MessagePayload const &message, MultiSignature const &sigma, GroupPublicKey const &gpk, GeneratorG2 const &generator_g2)
        {
            PublicKey tpk = AggregatePublicKey(gpk, sigma.second);

            if (tpk.isZero()) {
                return false;
            }


            std::string gtag_mess = gpk.tag.getStr() + message;

            Signature Hmess;
            bn::hashAndMapToG1(Hmess, gtag_mess);

            bn::Fp12  e1, e2;

            bn::pairing(e1, sigma.first, generator_g2);
            bn::pairing(e2, Hmess, tpk);

            return e1 == e2;
        }


        // aggregate_signature = multi_sig_1 multi_sig_2 ... multi_sig_k
        AggSignature AggregateSig(std::vector<MultiSignature> const &multi_signatures)
        {
          AggSignature aggregate_signature;

          for (auto const &msig : multi_signatures)
          {
            bn::G1::add(aggregate_signature.first, aggregate_signature.first, msig.first);
            aggregate_signature.second.push_back(msig.second);
          }
          return aggregate_signature;
        }



        bool VerifyAgg(std::vector<MessagePayload> const & messages, AggSignature const &aggregate_signature, std::vector<GroupPublicKey> const &gpks, GeneratorG2 const &generator_g2)
        {
          assert(messages.size() == gpks.size() && gpks.size() == aggregate_signature.second.size());

          std::vector<PublicKey> apks;
          apks.resize(gpks.size());
          for (uint32_t i = 0; i < gpks.size(); i++){
            apks[i] = AggregatePublicKey(gpks[i], aggregate_signature.second[i]);
          }

          bn::Fp12  e1, e2;
          e2.setOne();


          bn::pairing(e1,  aggregate_signature.first, generator_g2);

          for (uint32_t i = 0; i < gpks.size(); i++){
            std::string gtag_mess = gpks[i].tag.getStr() + messages[i];
            Signature Hmess;
            bn::hashAndMapToG1(Hmess, gtag_mess);

            bn::Fp12  tmp;
            bn::pairing(tmp,  Hmess, apks[i]);

            bn::GT::mul(e2, e2, tmp);

          }

          return e1 == e2;
        }




    }  // namespace mcl}  // namespace mcl
}  // namespace rsmspop
}  // namespace crypto
}  // namespace fetch
