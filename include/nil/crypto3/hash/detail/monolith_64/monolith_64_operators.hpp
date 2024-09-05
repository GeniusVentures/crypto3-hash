#ifndef CRYPTO3_HASH_MONOLITH_64_OPERATORS_HPP
#define CRYPTO3_HASH_MONOLITH_64_OPERATORS_HPP

#include <nil/crypto3/hash/detail/monolith_64/monolith_64_policy.hpp>
#include <nil/crypto3/algebra/matrix/matrix.hpp>
#include <nil/crypto3/algebra/matrix/math.hpp>
#include <nil/crypto3/algebra/matrix/operators.hpp>
#include <nil/crypto3/algebra/vector/vector.hpp>
#include <nil/crypto3/algebra/vector/math.hpp>
#include <nil/crypto3/algebra/vector/operators.hpp>

namespace nil {
    namespace crypto3 {
        namespace hashes {
            namespace detail {
                template<typename FieldType>
                struct monolith_64_operators {
                    typedef monolith_64_policy<FieldType> policy_type;

                    typedef typename policy_type::element_type element_type;
                    typedef typename element_type::integral_type integral_type;

                    constexpr static const std::size_t state_words = policy_type::state_words;
                    typedef algebra::vector<element_type, state_words> state_vector_type;
                    typedef algebra::matrix<element_type, state_words, state_words> mds_matrix_type;

                    mds_matrix_type mds_matrix;

                    monolith_64_operators() : mds_matrix(generate_mds_matrix()) {}

                    static inline mds_matrix_type generate_mds_matrix() {
                        // Implement MDS matrix generation for Monolith
                        // This is a placeholder and should be replaced with the actual MDS matrix
                        mds_matrix_type new_matrix;
                        for (int i = 0; i < state_words; ++i) {
                            for (int j = 0; j < state_words; ++j) {
                                new_matrix[i][j] = element_type(integral_type(i * state_words + j + 1));
                            }
                        }
                        return new_matrix;
                    }

                    inline void concrete(state_vector_type &A, std::size_t round) const {
                        A = algebra::matvectmul(mds_matrix, A);

                        // Add round constants (implement round constant generation)
                        for (int i = 0; i < state_words; ++i) {
                            A[i] += element_type(integral_type(round * state_words + i + 1));
                        }
                    }

                    static inline void bricks(state_vector_type &A) {
                        element_type tmp = A[0];
                        for (int i = 1; i < state_words; ++i) {
                            A[i] += tmp * tmp;
                            tmp = A[i];
                        }
                    }

                    static inline void bars(state_vector_type &A) {
                        for (int i = 0; i < policy_type::bars; ++i) {
                            bar(A[i]);
                        }
                    }

                    static inline void bar(element_type &el) {
                        integral_type x = el.data;
                        integral_type limbl1 = ((x & 0x8080808080808080) >> 7) | ((x & 0x7F7F7F7F7F7F7F7F) << 1);
                        integral_type limbl2 = ((x & 0xC0C0C0C0C0C0C0C0) >> 6) | ((x & 0x3F3F3F3F3F3F3F3F) << 2);
                        integral_type limbl3 = ((x & 0xE0E0E0E0E0E0E0E0) >> 5) | ((x & 0x1F1F1F1F1F1F1F1F) << 3);

                        integral_type tmp = x ^ (~limbl1 & limbl2 & limbl3);
                        el = element_type(((tmp & 0x8080808080808080) >> 7) | ((tmp & 0x7F7F7F7F7F7F7F7F) << 1));
                    }
                };
            }    // namespace detail
        }        // namespace hashes
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_HASH_MONOLITH_64_OPERATORS_HPP
