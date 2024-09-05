#ifndef CRYPTO3_HASH_MONOLITH_31_FUNCTIONS_HPP
#define CRYPTO3_HASH_MONOLITH_31_FUNCTIONS_HPP

#include <nil/crypto3/hash/detail/monolith_31/monolith_31_policy.hpp>
#include <nil/crypto3/hash/detail/monolith_31/monolith_31_operators.hpp>

namespace nil {
    namespace crypto3 {
        namespace hashes {
            namespace detail {
                template<typename FieldType, std::size_t T>
                struct monolith_31_functions : public monolith_31_policy<FieldType, T> {
                    typedef monolith_31_policy<FieldType, T> policy_type;
                    typedef typename policy_type::element_type element_type;
                    typedef typename policy_type::integral_type integral_type;
                    typedef typename policy_type::state_type state_type;

                    typedef monolith_31_operators<FieldType, T> operators_type;

                    static inline void permute(state_type &state) {
                        operators_type ops;
                        ops.concrete(state, 0);
                        for (std::size_t i = 1; i <= policy_type::R; ++i) {
                            ops.bars(state);
                            ops.bricks(state);
                            ops.concrete(state, i);
                        }
                    }
                };
            }  // namespace detail
        }  // namespace hashes
    }  // namespace crypto3
}  // namespace nil

#endif  // CRYPTO3_HASH_MONOLITH_31_FUNCTIONS_HPP
