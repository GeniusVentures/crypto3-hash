//---------------------------------------------------------------------------//
// Copyright (c) 2023 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2023 Nikita Kaskov <nbering@nil.foundation>
//
// MIT License
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_HASH_MONOLITH_MDS_HPP
#define CRYPTO3_HASH_MONOLITH_MDS_HPP

#include <nil/crypto3/hash/detail/monolith_mds/monolith_mds_policy.hpp>

namespace nil {
    namespace crypto3 {
        namespace hashes {

            template<typename FieldType>
            struct monolith_mds {
                typedef detail::monolith_mds_policy<FieldType> policy_type;
                typedef typename policy_type::element_type element_type;
                typedef typename policy_type::integral_type integral_type;

                template<std::size_t T>
                static std::array<std::array<element_type, T>, T> generate_mds() {
                    return policy_type::template generate_mds<T>();
                }
            };

        }  // namespace hashes
    }  // namespace crypto3
}  // namespace nil

#endif  // CRYPTO3_HASH_MONOLITH_MDS_HPP
