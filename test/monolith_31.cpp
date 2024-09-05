#define BOOST_TEST_MODULE monolith_31_test

#include <boost/test/unit_test.hpp>
#include <boost/multiprecision/cpp_int.hpp>
#include <nil/crypto3/hash/monolith_31.hpp>
#include <nil/crypto3/algebra/fields/bls12/scalar_field.hpp>
#include <nil/crypto3/algebra/random_element.hpp>

using namespace nil::crypto3;
using namespace nil::crypto3::algebra;
namespace mp = boost::multiprecision;

typedef fields::bls12_fr<381> field_type;
typedef hashes::monolith_31<field_type, 16> monolith_31_16;
typedef hashes::monolith_31<field_type, 24> monolith_31_24;

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

BOOST_AUTO_TEST_SUITE(monolith_31_tests)

BOOST_AUTO_TEST_CASE(consistent_perm_16) {
    monolith_31_16 monolith;

    for (std::size_t i = 0; i < TESTRUNS; ++i) {
        typename monolith_31_16::block_type input1, input2;

        for (auto &el : input1) {
            el = random_element<field_type>();
        }

        do {
            for (auto &el : input2) {
                el = random_element<field_type>();
            }
        } while (input1 == input2);

        typename monolith_31_16::state_type state1 = {}, state2 = {}, state3 = {};
        monolith.process_block(state1, input1);
        monolith.process_block(state2, input1);
        monolith.process_block(state3, input2);

        BOOST_CHECK_EQUAL_COLLECTIONS(state1.begin(), state1.end(), state2.begin(), state2.end());
        BOOST_CHECK(state1 != state3);
    }
}

BOOST_AUTO_TEST_CASE(kats_16) {
    monolith_31_16 monolith;

    typename monolith_31_16::block_type input;
    for (std::size_t i = 0; i < monolith_31_16::block_words; ++i) {
        input[i] = from_uint256(mp::uint256_t(i));
    }

    typename monolith_31_16::state_type state = {};
    monolith.process_block(state, input);

    BOOST_CHECK_EQUAL(state[0], from_uint256(mp::uint256_t("609156607")));
    BOOST_CHECK_EQUAL(state[1], from_uint256(mp::uint256_t("290107110")));
    BOOST_CHECK_EQUAL(state[2], from_uint256(mp::uint256_t("1900746598")));
    BOOST_CHECK_EQUAL(state[3], from_uint256(mp::uint256_t("1734707571")));
    BOOST_CHECK_EQUAL(state[4], from_uint256(mp::uint256_t("2050994835")));
    BOOST_CHECK_EQUAL(state[5], from_uint256(mp::uint256_t("1648553244")));
    BOOST_CHECK_EQUAL(state[6], from_uint256(mp::uint256_t("1307647296")));
    BOOST_CHECK_EQUAL(state[7], from_uint256(mp::uint256_t("1941164548")));
    BOOST_CHECK_EQUAL(state[8], from_uint256(mp::uint256_t("1707113065")));
    BOOST_CHECK_EQUAL(state[9], from_uint256(mp::uint256_t("1477714255")));
    BOOST_CHECK_EQUAL(state[10], from_uint256(mp::uint256_t("1170160793")));
    BOOST_CHECK_EQUAL(state[11], from_uint256(mp::uint256_t("93800695")));
    BOOST_CHECK_EQUAL(state[12], from_uint256(mp::uint256_t("769879348")));
    BOOST_CHECK_EQUAL(state[13], from_uint256(mp::uint256_t("375548503")));
    BOOST_CHECK_EQUAL(state[14], from_uint256(mp::uint256_t("1989726444")));
    BOOST_CHECK_EQUAL(state[15], from_uint256(mp::uint256_t("1349325635")));
}

BOOST_AUTO_TEST_CASE(kats_24) {
    monolith_31_24 monolith;

    typename monolith_31_24::block_type input;
    for (std::size_t i = 0; i < monolith_31_24::block_words; ++i) {
        input[i] = from_uint256(mp::uint256_t(i));
    }

    typename monolith_31_24::state_type state = {};
    monolith.process_block(state, input);

    BOOST_CHECK_EQUAL(state[0], from_uint256(mp::uint256_t("2067773075")));
    BOOST_CHECK_EQUAL(state[1], from_uint256(mp::uint256_t("1832201932")));
    BOOST_CHECK_EQUAL(state[2], from_uint256(mp::uint256_t("1944824478")));
    BOOST_CHECK_EQUAL(state[3], from_uint256(mp::uint256_t("1823377759")));
    BOOST_CHECK_EQUAL(state[4], from_uint256(mp::uint256_t("1441396277")));
    BOOST_CHECK_EQUAL(state[5], from_uint256(mp::uint256_t("2131077448")));
    BOOST_CHECK_EQUAL(state[6], from_uint256(mp::uint256_t("2132180368")));
    BOOST_CHECK_EQUAL(state[7], from_uint256(mp::uint256_t("1432941899")));
    BOOST_CHECK_EQUAL(state[8], from_uint256(mp::uint256_t("1347592327")));
    BOOST_CHECK_EQUAL(state[9], from_uint256(mp::uint256_t("1652902071")));
    BOOST_CHECK_EQUAL(state[10], from_uint256(mp::uint256_t("1809291778")));
    BOOST_CHECK_EQUAL(state[11], from_uint256(mp::uint256_t("1684517779")));
    BOOST_CHECK_EQUAL(state[12], from_uint256(mp::uint256_t("785982444")));
    BOOST_CHECK_EQUAL(state[13], from_uint256(mp::uint256_t("1037200378")));
    BOOST_CHECK_EQUAL(state[14], from_uint256(mp::uint256_t("1316286130")));
    BOOST_CHECK_EQUAL(state[15], from_uint256(mp::uint256_t("1391154514")));
    BOOST_CHECK_EQUAL(state[16], from_uint256(mp::uint256_t("1760346031")));
    BOOST_CHECK_EQUAL(state[17], from_uint256(mp::uint256_t("1412575993")));
    BOOST_CHECK_EQUAL(state[18], from_uint256(mp::uint256_t("2108791223")));
    BOOST_CHECK_EQUAL(state[19], from_uint256(mp::uint256_t("1657735769")));
    BOOST_CHECK_EQUAL(state[20], from_uint256(mp::uint256_t("219740691")));
    BOOST_CHECK_EQUAL(state[21], from_uint256(mp::uint256_t("1165267731")));
    BOOST_CHECK_EQUAL(state[22], from_uint256(mp::uint256_t("505815021")));
    BOOST_CHECK_EQUAL(state[23], from_uint256(mp::uint256_t("2080295871")));
}

// Note: We can't directly test the 'concrete' method or access the MDS matrix
// as they are likely private. Instead, we can test the overall behavior of the hash.

BOOST_AUTO_TEST_CASE(hash_consistency_16) {
    monolith_31_16 monolith;

    for (std::size_t i = 0; i < TESTRUNS; ++i) {
        typename monolith_31_16::block_type input;
        for (auto& el : input) {
            el = random_element<field_type>();
        }

        typename monolith_31_16::state_type state1 = {}, state2 = {};
        monolith.process_block(state1, input);
        monolith.process_block(state2, input);

        BOOST_CHECK_EQUAL_COLLECTIONS(state1.begin(), state1.end(), state2.begin(), state2.end());
    }
}

BOOST_AUTO_TEST_CASE(hash_consistency_24) {
    monolith_31_24 monolith;

    for (std::size_t i = 0; i < TESTRUNS; ++i) {
        typename monolith_31_24::block_type input;
        for (auto& el : input) {
            el = random_element<field_type>();
        }

        typename monolith_31_24::state_type state1 = {}, state2 = {};
        monolith.process_block(state1, input);
        monolith.process_block(state2, input);

        BOOST_CHECK_EQUAL_COLLECTIONS(state1.begin(), state1.end(), state2.begin(), state2.end());
    }
}

BOOST_AUTO_TEST_SUITE_END()
