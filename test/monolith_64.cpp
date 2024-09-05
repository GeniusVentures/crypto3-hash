#define BOOST_TEST_MODULE monolith_64_test

#include <boost/test/unit_test.hpp>
#include <boost/multiprecision/cpp_int.hpp>
#include <nil/crypto3/hash/monolith_64.hpp>
#include <nil/crypto3/algebra/fields/bls12/scalar_field.hpp>
#include <nil/crypto3/algebra/random_element.hpp>

using namespace nil::crypto3;
using namespace nil::crypto3::algebra;
namespace mp = boost::multiprecision;

typedef fields::bls12_fr<381> field_type;
typedef hashes::monolith_64<field_type, 8> monolith_64_8;
typedef hashes::monolith_64<field_type, 12> monolith_64_12;

constexpr std::size_t TESTRUNS = 5;

// Helper function to generate random field elements
template<typename FieldType>
typename FieldType::value_type random_element() {
    return random_element<FieldType>();
}

// Helper function to convert mp::uint256_t to field element
template<typename FieldType>
typename FieldType::value_type from_uint256(const mp::uint256_t& value) {
    return typename FieldType::value_type(value);
}

BOOST_AUTO_TEST_SUITE(monolith_64_tests)

BOOST_AUTO_TEST_CASE(consistent_perm_8) {
        monolith_64_8 monolith;

        for (std::size_t i = 0; i < TESTRUNS; ++i) {
            typename monolith_64_8::block_type input1, input2;

            for (auto &el : input1) {
                el = random_element<field_type>();
            }

            do {
                for (auto &el : input2) {
                    el = random_element<field_type>();
                }
            } while (input1 == input2);

            typename monolith_64_8::state_type state1 = {}, state2 = {}, state3 = {};
            monolith.process_block(state1, input1);
            monolith.process_block(state2, input1);
            monolith.process_block(state3, input2);

            BOOST_CHECK_EQUAL_COLLECTIONS(state1.begin(), state1.end(), state2.begin(), state2.end());
            BOOST_CHECK(state1 != state3);
        }
}

BOOST_AUTO_TEST_CASE(kats_8) {
        monolith_64_8 monolith;

        typename monolith_64_8::block_type input;
        for (std::size_t i = 0; i < monolith_64_8::block_words; ++i) {
            input[i] = from_uint256(mp::uint256_t(i));
        }

        typename monolith_64_8::state_type state = {};
        monolith.process_block(state, input);

        BOOST_CHECK_EQUAL(state[0], from_uint256(mp::uint256_t("3656442354255169651")));
        BOOST_CHECK_EQUAL(state[1], from_uint256(mp::uint256_t("1088199316401146975")));
        BOOST_CHECK_EQUAL(state[2], from_uint256(mp::uint256_t("22941152274975507")));
        BOOST_CHECK_EQUAL(state[3], from_uint256(mp::uint256_t("14434181924633355796")));
        BOOST_CHECK_EQUAL(state[4], from_uint256(mp::uint256_t("6981961052218049719")));
        BOOST_CHECK_EQUAL(state[5], from_uint256(mp::uint256_t("16492720827407246378")));
        BOOST_CHECK_EQUAL(state[6], from_uint256(mp::uint256_t("17986182688944525029")));
        BOOST_CHECK_EQUAL(state[7], from_uint256(mp::uint256_t("9161400698613172623")));
}

BOOST_AUTO_TEST_CASE(kats_12) {
        monolith_64_12 monolith;

        typename monolith_64_12::block_type input;
        for (std::size_t i = 0; i < monolith_64_12::block_words; ++i) {
            input[i] = from_uint256(mp::uint256_t(i));
        }

        typename monolith_64_12::state_type state = {};
        monolith.process_block(state, input);

        BOOST_CHECK_EQUAL(state[0], from_uint256(mp::uint256_t("5867581605548782913")));
        BOOST_CHECK_EQUAL(state[1], from_uint256(mp::uint256_t("588867029099903233")));
        BOOST_CHECK_EQUAL(state[2], from_uint256(mp::uint256_t("6043817495575026667")));
        BOOST_CHECK_EQUAL(state[3], from_uint256(mp::uint256_t("805786589926590032")));
        BOOST_CHECK_EQUAL(state[4], from_uint256(mp::uint256_t("9919982299747097782")));
        BOOST_CHECK_EQUAL(state[5], from_uint256(mp::uint256_t("6718641691835914685")));
        BOOST_CHECK_EQUAL(state[6], from_uint256(mp::uint256_t("7951881005429661950")));
        BOOST_CHECK_EQUAL(state[7], from_uint256(mp::uint256_t("15453177927755089358")));
        BOOST_CHECK_EQUAL(state[8], from_uint256(mp::uint256_t("974633365445157727")));
        BOOST_CHECK_EQUAL(state[9], from_uint256(mp::uint256_t("9654662171963364206")));
        BOOST_CHECK_EQUAL(state[10], from_uint256(mp::uint256_t("6281307445101925412")));
        BOOST_CHECK_EQUAL(state[11], from_uint256(mp::uint256_t("13745376999934453119")));
}

// Note: We can't directly test the 'concrete' method or access the MDS matrix
// as they are likely private. Instead, we can test the overall behavior of the hash.

BOOST_AUTO_TEST_CASE(hash_consistency_8) {
        monolith_64_8 monolith;

        for (std::size_t i = 0; i < TESTRUNS; ++i) {
            typename monolith_64_8::block_type input;
            for (auto& el : input) {
                el = random_element<field_type>();
            }

            typename monolith_64_8::state_type state1 = {}, state2 = {};
            monolith.process_block(state1, input);
            monolith.process_block(state2, input);

            BOOST_CHECK_EQUAL_COLLECTIONS(state1.begin(), state1.end(), state2.begin(), state2.end());
        }
}

BOOST_AUTO_TEST_CASE(hash_consistency_12) {
        monolith_64_12 monolith;

        for (std::size_t i = 0; i < TESTRUNS; ++i) {
            typename monolith_64_12::block_type input;
            for (auto& el : input) {
                el = random_element<field_type>();
            }

            typename monolith_64_12::state_type state1 = {}, state2 = {};
            monolith.process_block(state1, input);
            monolith.process_block(state2, input);

            BOOST_CHECK_EQUAL_COLLECTIONS(state1.begin(), state1.end(), state2.begin(), state2.end());
        }
}

BOOST_AUTO_TEST_SUITE_END()
