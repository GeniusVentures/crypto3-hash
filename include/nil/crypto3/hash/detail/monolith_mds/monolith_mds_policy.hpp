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

#ifndef CRYPTO3_HASH_DETAIL_MONOLITH_MDS_POLICY_HPP
#define CRYPTO3_HASH_DETAIL_MONOLITH_MDS_POLICY_HPP

#include <array>
#include <cstdint>
#include <type_traits>
#include <nil/crypto3/hash/shake128.hpp>

namespace nil {
    namespace crypto3 {
        namespace hashes {
            namespace detail {

                template<typename FieldType>
                struct monolith_mds_policy {
                    using element_type = typename FieldType::value_type;
                    using integral_type = typename element_type::integral_type;
                    constexpr static const char* INIT_SHAKE = "Monolith";

                    template<std::size_t T>
                    static std::array<std::array<element_type, T>, T> generate_mds() {
                        if constexpr (T == 8) {
                            return generate_mds_8();
                        } else if constexpr (T == 12) {
                            return generate_mds_12();
                        } else if constexpr (T == 16) {
                            return generate_mds_16();
                        } else if constexpr (T == 24) {
                            return generate_mds_24();
                        } else {
                            return cauchy_mds_matrix<T>();
                        }
                    }

                private:
                    static std::array<std::array<element_type, 8>, 8> generate_mds_8() {
                        const std::array<integral_type, 8> row = {23, 8, 13, 10, 7, 6, 21, 8};
                        return circ_mat<8>(row);
                    }

                    static std::array<std::array<element_type, 12>, 12> generate_mds_12() {
                        const std::array<integral_type, 12> row = {7, 23, 8, 26, 13, 10, 9, 7, 6, 22, 21, 8};
                        return circ_mat<12>(row);
                    }

                    static std::array<std::array<element_type, 16>, 16> generate_mds_16() {
                        const std::array<integral_type, 16> row = {
                            61402, 17845, 26798, 59689, 12021, 40901, 41351, 27521,
                            56951, 12034, 53865, 43244, 7454, 33823, 28750, 1108
                        };
                        return circ_mat<16>(row);
                    }

                    static std::array<std::array<element_type, 24>, 24> generate_mds_24() {
                        const std::array<integral_type, 24> row = {
                            87474966, 500304516, 1138910529, 1387408269, 937082352, 1410252806,
                            806711693, 1520034124, 593719941, 1284124534, 1575767662, 927918294,
                            669885656, 1717383379, 853820823, 1137173171, 1740948995, 2024301343,
                            1160738787, 60752863, 1950203872, 1302354504, 1593997632, 136918578
                        };
                        return circ_mat<24>(row);
                    }

                    template<std::size_t T>
                    static std::array<std::array<element_type, T>, T> circ_mat(const std::array<integral_type, T>& row) {
                        std::array<std::array<element_type, T>, T> mat;
                        std::array<element_type, T> rot;
                        std::transform(row.begin(), row.end(), rot.begin(), [](integral_type i) { return element_type(i); });
                        
                        for (std::size_t i = 0; i < T; ++i) {
                            std::copy(rot.begin(), rot.end(), mat[i].begin());
                            std::rotate(rot.begin(), rot.begin() + 1, rot.end());
                        }
                        return mat;
                    }

                    template<std::size_t T>
                    static std::array<std::array<element_type, T>, T> cauchy_mds_matrix() {
                        hashes::shake128 shake;
                        shake.update(INIT_SHAKE, std::strlen(INIT_SHAKE));
                        shake.update(std::array<uint8_t, 1>{static_cast<uint8_t>(T)});
                        shake.update(std::array<uint8_t, 1>{static_cast<uint8_t>(6)}); // Assuming R = 6
                        auto p = FieldType::modulus;
                        shake.update(reinterpret_cast<const uint8_t*>(&p), sizeof(p));
                        shake.update(std::array<uint8_t, 2>{16, 15});
                        shake.update("MDS", 3);

                        integral_type tmp = 0;
                        while (p != 0) {
                            tmp += 1;
                            p >>= 1;
                        }

                        integral_type x_mask = (1 << (tmp - 7 - 2)) - 1;
                        integral_type y_mask = ((1 << tmp) - 1) >> 2;

                        std::array<std::array<element_type, T>, T> res;
                        std::array<integral_type, T> y = get_random_yi<T>(shake, x_mask, y_mask);
                        std::array<integral_type, T> x = y;
                        
                        for (auto& xi : x) {
                            xi &= x_mask;
                        }

                        for (std::size_t i = 0; i < T; ++i) {
                            for (std::size_t j = 0; j < T; ++j) {
                                res[i][j] = element_type(x[i] + y[j]).inversed();
                            }
                        }

                        return res;
                    }

                    template<std::size_t T>
                    static std::array<integral_type, T> get_random_yi(hashes::shake128& shake, integral_type x_mask, integral_type y_mask) {
                        std::array<integral_type, T> res;
                        for (std::size_t i = 0; i < T; ++i) {
                            integral_type y_i;
                            do {
                                shake.read(reinterpret_cast<uint8_t*>(&y_i), sizeof(y_i));
                                y_i &= y_mask;
                            } while (std::find(res.begin(), res.begin() + i, y_i & x_mask) != res.begin() + i);
                            res[i] = y_i;
                        }
                        return res;
                    }
                };

            }  // namespace detail
        }  // namespace hashes
    }  // namespace crypto3
}  // namespace nil

#endif  // CRYPTO3_HASH_DETAIL_MONOLITH_MDS_POLICY_HPP
