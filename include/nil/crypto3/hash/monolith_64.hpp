#ifndef CRYPTO3_HASH_MONOLITH_64_HPP
#define CRYPTO3_HASH_MONOLITH_64_HPP

#include "detail/monolith_64/monolith_64_policy.hpp"
#include "detail/monolith_64/monolith_64_functions.hpp"

namespace nil {
    namespace crypto3 {
        namespace hashes {
            template<typename FieldType>
            struct monolith_64_compressor {
                typedef detail::monolith_64_functions<FieldType> policy_type;
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
                    for (int i = 0; i < block_words; ++i) {
                        state[i] ^= block[i];
                    }

                    policy_type::permute(state);
                }
            };

            template<typename FieldType>
            using monolith_64 = monolith_64_compressor<FieldType>;

        }  // namespace hashes
    }  // namespace crypto3
}  // namespace nil

#endif  // CRYPTO3_HASH_MONOLITH_64_HPP
