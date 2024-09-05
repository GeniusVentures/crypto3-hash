#ifndef CRYPTO3_HASH_MONOLITH_64_FUNCTIONS_HPP
#define CRYPTO3_HASH_MONOLITH_64_FUNCTIONS_HPP

#include <nil/crypto3/hash/detail/monolith_64/monolith_64_policy.hpp>
#include <nil/crypto3/hash/detail/monolith_64/monolith_64_operators.hpp>
#include <algorithm>

namespace nil {
    namespace crypto3 {
        namespace hashes {
            namespace detail {
                template<typename FieldType>
                struct monolith_64_functions {
                    typedef monolith_64_policy<FieldType> policy_type;
                    typedef typename policy_type::element_type element_type;
                    typedef typename policy_type::integral_type integral_type;

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

                    constexpr static const std::size_t rounds = policy_type::rounds;

                    typedef monolith_64_operators<FieldType> monolith_64_operators_type;
                    typedef typename monolith_64_operators_type::state_vector_type state_vector_type;

                    static monolith_64_operators_type get_monolith_64_operators_type() {
                        return monolith_64_operators_type();
                    }

                    static inline const monolith_64_operators_type monolith_64_operators = get_monolith_64_operators_type();

                    static inline void permute(state_type &A) {
                        state_vector_type A_vector;
                        std::copy(A.begin(), A.end(), A_vector.begin());

                        monolith_64_operators.concrete(A_vector, 0);
                        for (int i = 1; i <= rounds; ++i) {
                            monolith_64_operators.bars(A_vector);
                            monolith_64_operators.bricks(A_vector);
                            monolith_64_operators.concrete(A_vector, i);
                        }

                        std::copy(A_vector.begin(), A_vector.end(), A.begin());
                    }
                };
            }    // namespace detail
        }        // namespace hashes
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_HASH_MONOLITH_64_FUNCTIONS_HPP
