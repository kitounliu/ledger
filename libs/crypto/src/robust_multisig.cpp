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

#include "crypto/robust_multisig.hpp"
#include "mcl/bn256.hpp"

#include <cassert>
#include <cstddef>
#include <stdexcept>
#include <unordered_map>

namespace bn = mcl::bn256;

namespace fetch {
namespace crypto {
namespace rsms {
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
    std::pair<PrivateKey, PublicVerifyKey> GenerateKeyPair(GeneratorG2 const &generator_g2)
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


     bool GroupPublicKey::GroupSet(std::vector<PublicVerifyKey> const &public_verify_keys, GeneratorG2 const &generator_g2){

         for (const auto & public_verify_key : public_verify_keys){
             if (!public_verify_key.Validate(generator_g2)) return false;
         }

         for (size_t i = 0; i < public_verify_keys.size(); i++){
             bn::G2::add(aggregate_public_key, aggregate_public_key, public_verify_keys[i].public_key);
         }

         public_verify_key_list.insert(public_verify_key_list.end(), public_verify_keys.begin(),public_verify_keys.end());

         return true;
    }


    /**
 * Computes signature share of a message
 *
 * @param message Message to be signed
 * @param x_i Secret key share
 * @return Signature share
 */
    Signature Sign(PublicKey const &aggregate_public_key, MessagePayload const &message, PrivateKey const &sk, GeneratorG2 const &generator_g2)
    {
        std::string apk_mess = aggregate_public_key.getStr() + message;

        Signature Hmess;
        Signature sig;
        bn::hashAndMapToG1(Hmess, apk_mess);

        bn::G1::mul(sig, Hmess, sk);  // sign = s H(m)

        PublicKey pk;
        bn::G2::mul(pk, generator_g2, sk);

        return sig;
    }


// create a NIZK proof
    Proof Prove(const PublicVerifyKey &public_verify_key, const PublicKey &aggregate_public_key, const MessagePayload &message, const Signature &sig,
                           const PrivateKey &sk) {
        std::string apk_mess = aggregate_public_key.getStr() + message;

        Signature Hmess;
        bn::hashAndMapToG1(Hmess, apk_mess);

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
        return pi;
    }

// verify a NIZK proof (sig, pi)
        bool Verify(const PublicVerifyKey &public_verify_key, const PublicKey &aggregate_public_key, const MessagePayload &message, const Signature &sig, const Proof &pi) {
            std::string apk_mess = aggregate_public_key.getStr() + message;

            Signature Hmess;
            bn::hashAndMapToG1(Hmess, apk_mess);

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
        bool VerifySlow(PublicKey const &pk, PublicKey const &aggregate_public_key,  MessagePayload const &message, Signature const &sig,
                        GeneratorG2 const &generator_g2)
        {
            std::string apk_mess = aggregate_public_key.getStr() + message;

            Signature Hmess;
            bn::hashAndMapToG1(Hmess, apk_mess);

            bn::Fp12  e1, e2;

            bn::pairing(e1, sig, generator_g2);
            bn::pairing(e2, Hmess, pk);

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
            Signature    aggregate_signature;
            SignerRecord signers;
            signers.resize(cabinet_size, 0);

            // Add individual signatures to compute aggregate signature
            for (auto const &sig : signatures)
            {
                bn::G1::add(aggregate_signature, aggregate_signature, sig.second);
                signers[sig.first] = 1;
            }
            return std::make_pair(aggregate_signature, signers);
        }


        bool VerifyMulti(MessagePayload const &message, MultiSignature const &sigma, GroupPublicKey const &gpk, GeneratorG2 const &generator_g2)
        {
            PublicKey tpk;

            assert(sigma.second.size() <= gpk.public_verify_key_list.size());

            for(uint32_t i = 0; i<sigma.second.size();i++){
                if (sigma.second[i]==1) {
                    bn::G2::add(tpk, tpk, gpk.public_verify_key_list[i].public_key);
                }
            }

            if (tpk.isZero()) {
                return false;
            }


            std::string apk_mess = gpk.aggregate_public_key.getStr() + message;

            Signature Hmess;
            bn::hashAndMapToG1(Hmess, apk_mess);

            bn::Fp12  e1, e2;

            bn::pairing(e1, sigma.first, generator_g2);
            bn::pairing(e2, Hmess, tpk);

            return e1 == e2;
        }

    }  // namespace mcl}  // namespace mcl
}  // namespace rsms
}  // namespace crypto
}  // namespace fetch
