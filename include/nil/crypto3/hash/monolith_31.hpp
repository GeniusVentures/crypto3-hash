#ifndef CRYPTO3_HASH_MONOLITH_31_HPP
#define CRYPTO3_HASH_MONOLITH_31_HPP

#include <nil/crypto3/hash/detail/monolith_31/monolith_31_policy.hpp>
#include <nil/crypto3/hash/detail/monolith_31/monolith_31_functions.hpp>

namespace nil {
    namespace crypto3 {
        namespace hashes {
            template<typename FieldType, std::size_t T>
            struct monolith_31_compressor {
                typedef detail::monolith_31_functions<FieldType, T> policy_type;
                typedef typename policy_type::element_type element_type;

                constexpr static const std::size_t word_bits = policy_type::word_bits;
                typedef typename policy_type::word_type word_type;

                constexpr static const std::size_t digest_bits = policy_type::digest_bits;
                typedef typename policy_type::digest_type digest_type;

                constexpr static const std::size_t block_words = policy_type::block_words;
                constexpr static const std::size_t block_bits = policy_type::block_bits;
                typedef typename policy_type::block_type block_type;

                constexpr static const std::size_t state_words = policy_type::state_words;
                constexpr static const std::size_t state_bits = policy_type::state_bits;
                typedef typename policy_type::state_type state_type;

                static inline void process_block(state_type &state, const block_type &block) {
                    for (std::size_t i = 0; i < block_words; ++i) {
                        state[i] ^= block[i];
                    }

                    policy_type::permute(state);
                }
            };

            template<typename FieldType, std::size_t T>
            using monolith_31 = monolith_31_compressor<FieldType, T>;

        }  // namespace hashes
    }  // namespace crypto3
}  // namespace nil

#endif  // CRYPTO3_HASH_MONOLITH_31_HPP
