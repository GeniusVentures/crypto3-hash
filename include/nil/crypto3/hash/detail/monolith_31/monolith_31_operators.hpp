#ifndef CRYPTO3_HASH_MONOLITH_31_OPERATORS_HPP
#define CRYPTO3_HASH_MONOLITH_31_OPERATORS_HPP

#include <nil/crypto3/hash/detail/monolith_31/monolith_31_policy.hpp>

namespace nil {
    namespace crypto3 {
        namespace hashes {
            namespace detail {
                template<typename FieldType, std::size_t T>
                struct monolith_31_operators : public monolith_31_policy<FieldType, T> {
                    typedef monolith_31_policy<FieldType, T> policy_type;
                    typedef typename policy_type::element_type element_type;
                    typedef typename policy_type::integral_type integral_type;
                    typedef typename policy_type::state_type state_type;

                    void concrete(state_type &state, std::size_t round) const {
                        state_type temp;
                        for (std::size_t i = 0; i < T; ++i) {
                            temp[i] = policy_type::round_constants[round][i];
                            for (std::size_t j = 0; j < T; ++j) {
                                temp[i] += policy_type::mds[i][j] * state[j];
                            }
                        }
                        state = temp;
                    }

                    static void bricks(state_type &state) {
                        element_type tmp = state[0];
                        for (std::size_t i = 1; i < T; ++i) {
                            state[i] += tmp * tmp;
                            tmp = state[i];
                        }
                    }

                    void bars(state_type &state) const {
                        for (std::size_t i = 0; i < policy_type::BARS; ++i) {
                            bar(state[i]);
                        }
                    }

                    void bar(element_type &el) const {
                        integral_type x = el.data;
                        integral_type low = bar0_24(x & 0xFFFFFF);
                        integral_type high = bar1_7((x >> 24) & 0x7F);
                        el = element_type(low | (high << 24));
                    }

                    static integral_type bar0_24(integral_type limb) {
                        integral_type limbl1 = ((limb & 0x808080) >> 7) | ((limb & 0x7F7F7F) << 1);
                        integral_type limbl2 = ((limb & 0xC0C0C0) >> 6) | ((limb & 0x3F3F3F) << 2);
                        integral_type limbl3 = ((limb & 0xE0E0E0) >> 5) | ((limb & 0x1F1F1F) << 3);

                        integral_type tmp = limb ^ (~limbl1 & limbl2 & limbl3);
                        return ((tmp & 0x808080) >> 7) | ((tmp & 0x7F7F7F) << 1);
                    }

                    static integral_type bar1_7(integral_type limb) {
                        integral_type limbl1 = (limb >> 6) | (limb << 1);
                        integral_type limbl2 = (limb >> 5) | (limb << 2);

                        integral_type tmp = (limb ^ ~limbl1 & limbl2) & 0x7F;
                        return ((tmp >> 6) | (tmp << 1)) & 0x7F;
                    }
                };
            }  // namespace detail
        }  // namespace hashes
    }  // namespace crypto3
}  // namespace nil

#endif  // CRYPTO3_HASH_MONOLITH_31_OPERATORS_HPP
