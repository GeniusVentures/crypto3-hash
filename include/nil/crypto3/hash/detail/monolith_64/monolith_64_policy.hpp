#ifndef CRYPTO3_HASH_MONOLITH_64_POLICY_HPP
#define CRYPTO3_HASH_MONOLITH_64_POLICY_HPP

#include <array>
#include <nil/crypto3/algebra/fields/bls12/scalar_field.hpp>

namespace nil {
    namespace crypto3 {
        namespace hashes {
            namespace detail {
                template<typename FieldType>
                struct base_monolith_64_policy {
                    typedef FieldType field_type;
                    typedef typename field_type::value_type element_type;
                    typedef typename element_type::integral_type integral_type;
                    constexpr static const std::size_t word_bits = 64;
                    typedef element_type word_type;

                    constexpr static const std::size_t digest_bits = 256;
                    typedef std::array<element_type, digest_bits / word_bits> digest_type;

                    constexpr static const std::size_t block_words = 8;
                    constexpr static const std::size_t block_bits = block_words * word_bits;
                    typedef std::array<element_type, block_words> block_type;

                    constexpr static const std::size_t state_words = 8;
                    constexpr static const std::size_t state_bits = state_words * word_bits;
                    typedef std::array<element_type, state_words> state_type;

                    constexpr static const std::size_t rounds = 6;
                    constexpr static const std::size_t bars = 4;
                };

                template<typename FieldType>
                struct monolith_64_policy;

                template<>
                struct monolith_64_policy<nil::crypto3::algebra::fields::bls12_fr<381>>
                        : public base_monolith_64_policy<nil::crypto3::algebra::fields::bls12_fr<381>> {
                    // Add any specific constants or parameters for BLS12-381 field if needed
                };
            }    // namespace detail
        }        // namespace hashes
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_HASH_MONOLITH_64_POLICY_HPP
