#ifndef CRYPTO3_HASH_MONOLITH_31_POLICY_HPP
#define CRYPTO3_HASH_MONOLITH_31_POLICY_HPP

#include <array>
#include <vector>
#include <nil/crypto3/algebra/fields/bls12/scalar_field.hpp>

namespace nil {
    namespace crypto3 {
        namespace hashes {
            namespace detail {
                template<typename FieldType, std::size_t T>
                struct monolith_31_policy {
                    typedef FieldType field_type;
                    typedef typename field_type::value_type element_type;
                    typedef typename element_type::integral_type integral_type;
                    
                    constexpr static const std::size_t word_bits = 31;
                    typedef element_type word_type;

                    constexpr static const std::size_t digest_bits = 256;
                    typedef std::array<element_type, digest_bits / word_bits> digest_type;

                    constexpr static const std::size_t block_words = T / 2;
                    constexpr static const std::size_t block_bits = block_words * word_bits;
                    typedef std::array<element_type, block_words> block_type;

                    constexpr static const std::size_t state_words = T;
                    constexpr static const std::size_t state_bits = state_words * word_bits;
                    typedef std::array<element_type, state_words> state_type;

                    constexpr static const std::size_t R = 6;
                    constexpr static const std::size_t BARS = 8;

                    typedef std::array<element_type, state_words> round_constants_type;
                    typedef std::array<std::array<element_type, state_words>, state_words> mds_matrix_type;

                    static constexpr const char* INIT_SHAKE = "Monolith";

                    std::vector<round_constants_type> round_constants;
                    mds_matrix_type mds;
                    std::vector<uint16_t> lookup1;
                    std::vector<uint16_t> lookup2;

                    monolith_31_policy();
                };
            }  // namespace detail
        }  // namespace hashes
    }  // namespace crypto3
}  // namespace nil

#endif  // CRYPTO3_HASH_MONOLITH_31_POLICY_HPP
