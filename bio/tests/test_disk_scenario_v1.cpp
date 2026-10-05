#include "disk_scenario_v1.hpp"

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <vector>

namespace {

void require(bool value, const char *message)
{
  if (!value) {
    std::cerr << "FAIL: " << message << "\n";
    std::exit(1);
  }
}

std::vector<std::uint8_t> make_sample(std::uint8_t planetClass)
{
  const std::size_t size = gwscenario::kWirePayloadEnd +
      gwscenario::kTailPrefixBytes + 7;
  std::vector<std::uint8_t> bytes(size);
  for (std::size_t i = 0; i < bytes.size(); ++i)
    bytes[i] = static_cast<std::uint8_t>((i * 37u + 11u) & 0xffu);

  bytes[0] = 0x36;
  bytes[1] = 0x53;
  bytes[2] = 0x05;
  bytes[3] = 0x00;
  bytes[gwscenario::kPlanetClassFileOffset] = planetClass;
  for (std::size_t i = 0; i < gwscenario::kTailPrefixBytes; ++i)
    bytes[gwscenario::kWirePayloadEnd + i] = 0;
  return bytes;
}

bool same_bytes(const std::uint8_t *a, const std::uint8_t *b,
    std::size_t size)
{
  return std::equal(a, a + size, b);
}

template<typename Record>
bool all_records_match(const std::vector<std::uint8_t> &input,
    const std::vector<Record> &records, std::size_t offset)
{
  for (std::size_t i = 0; i < records.size(); ++i) {
    if (!same_bytes(records[i].bytes.data(),
        input.data() + offset + i * Record::wire_stride,
        Record::wire_stride))
      return false;
  }
  return true;
}

void check_sample(const std::vector<std::uint8_t> &input,
    std::uint8_t expectedPlanetClass)
{
  gwscenario::DiskScenarioV1 scenario;
  gwscenario::DiskScenarioError error = gwscenario::DiskScenarioError::none;
  require(gwscenario::parse_disk_scenario_v1(input.data(), input.size(),
      scenario, &error), gwscenario::disk_scenario_error_name(error));
  require(scenario.source_file_size == input.size(), "source file size");
  require(scenario.signature == 0x55336, "magic");
  require(scenario.players.size() == 4 &&
      scenario.players[0].bytes.size() == 0x70D, "player records");
  require(scenario.world.size() == 0x4000 &&
      scenario.world[0].bytes.size() == 0x0E, "world records");
  require(scenario.family_A.size() == 300 &&
      scenario.family_A[0].bytes.size() == 0x74 &&
      scenario.family_A[0].runtime_stride == 0x7C, "family A strides");
  require(scenario.family_B.size() == 512 &&
      scenario.family_B[0].bytes.size() == 0x29 &&
      scenario.family_B[0].runtime_stride == 0x31, "family B strides");
  require(scenario.family_C.size() == 20 &&
      scenario.family_C[0].bytes.size() == 0x8C &&
      scenario.family_C[0].runtime_stride == 0xC8, "family C strides");
  require(scenario.family_D.size() == 256 &&
      scenario.family_D[0].bytes.size() == 0x3B &&
      scenario.family_D[0].runtime_stride == 0x43, "family D strides");
  require(scenario.family_E.size() == 200 &&
      scenario.family_E[0].bytes.size() == 0x49 &&
      scenario.family_E[0].runtime_stride == 0x51, "family E strides");
  require(scenario.family_F.size() == 32 &&
      scenario.family_F[0].bytes.size() == 0x29 &&
      scenario.family_F[0].runtime_stride == 0x31, "family F strides");
  require(scenario.family_G.size() == 32 &&
      scenario.family_G[0].bytes.size() == 0x59 &&
      scenario.family_G[0].runtime_stride == 0x61, "family G strides");
  require(scenario.family_H.size() == 16 &&
      scenario.family_H[0].bytes.size() == 0x5E &&
      scenario.family_H[0].runtime_stride == 0x66, "family H strides");

  const std::size_t begins[8] = {
    0x3B55E, 0x43D4E, 0x48F4E, 0x49A3E,
    0x4D53E, 0x50E46, 0x51366, 0x51E86
  };
  const std::size_t ends[8] = {
    0x43D4E, 0x48F4E, 0x49A3E, 0x4D53E,
    0x50E46, 0x51366, 0x51E86, 0x52466
  };
  for (std::size_t i = 0; i < 8; ++i) {
    require(scenario.family_ranges[i].begin == begins[i] &&
        scenario.family_ranges[i].end == ends[i] &&
        scenario.family_ranges[i].size() == ends[i] - begins[i],
        "family serialized range");
  }
  require(scenario.planetClass == expectedPlanetClass, "planet class");
  require(scenario.b32_letter() == static_cast<char>('a' + expectedPlanetClass),
      "B32 class letter");
  require(scenario.b32_filename() == std::string("data\\b32") +
      static_cast<char>('a' + expectedPlanetClass) + ".dat", "B32 filename");
  require(scenario.tail_begin == gwscenario::kWirePayloadEnd &&
      scenario.parsed_cursor() == scenario.tail_begin +
          gwscenario::kTailPrefixBytes, "tail cursor");
  require(scenario.trailing_opaque_size() == input.size() -
      scenario.parsed_cursor(), "opaque tail size");

  require(same_bytes(scenario.prefix_before_players.data(), input.data() + 4,
      scenario.prefix_before_players.size()), "prefix bytes preserved");
  require(same_bytes(scenario.players[0].bytes.data(), input.data() + 0x14,
      0x70D), "first player bytes preserved");
  require(same_bytes(scenario.players[3].bytes.data(), input.data() + 0x14 +
      3 * 0x70D, 0x70D), "last player bytes preserved");
  require(same_bytes(scenario.world[0].bytes.data(), input.data() + 0x355E,
      0x0E), "first world bytes preserved");
  require(same_bytes(scenario.world[0x3FFF].bytes.data(),
      input.data() + 0x3B550, 0x0E), "last world bytes preserved");
  require(scenario.world[0].byte_0C() == input[0x356A],
      "world byte +0xC accessor");
  require(all_records_match(input, scenario.family_A, begins[0]) &&
      all_records_match(input, scenario.family_B, begins[1]) &&
      all_records_match(input, scenario.family_C, begins[2]) &&
      all_records_match(input, scenario.family_D, begins[3]) &&
      all_records_match(input, scenario.family_E, begins[4]) &&
      all_records_match(input, scenario.family_F, begins[5]) &&
      all_records_match(input, scenario.family_G, begins[6]) &&
      all_records_match(input, scenario.family_H, begins[7]),
      "all record bytes preserved");
  require(same_bytes(scenario.opaque_tail_bytes.data(),
      input.data() + scenario.tail_begin, scenario.opaque_tail_bytes.size()),
      "tail bytes preserved");
}

void check_file_loader(const std::vector<std::uint8_t> &input)
{
  const char *path = "test_disk_scenario_v1.tmp";
  std::ifstream existing(path, std::ios::binary);
  require(!existing.good(), "temporary test path is unused");

  {
    std::ofstream output(path, std::ios::binary | std::ios::out);
    require(static_cast<bool>(output), "create temporary scenario");
    output.write(reinterpret_cast<const char *>(input.data()),
        static_cast<std::streamsize>(input.size()));
    require(static_cast<bool>(output), "write temporary scenario");
  }

  gwscenario::DiskScenarioV1 parsed;
  gwscenario::DiskScenarioError error = gwscenario::DiskScenarioError::none;
  const bool ok = gwscenario::parse_disk_scenario_v1_file(path, parsed, &error);
  const int removeResult = std::remove(path);
  require(ok, gwscenario::disk_scenario_error_name(error));
  require(removeResult == 0, "remove generated temporary scenario");
  require(parsed.parsed_cursor() == gwscenario::kWirePayloadEnd +
      gwscenario::kTailPrefixBytes, "file and buffer parsers agree");
}

void check_failures(const std::vector<std::uint8_t> &sample)
{
  gwscenario::DiskScenarioV1 output;
  output.signature = 0x12345678;
  gwscenario::DiskScenarioError error = gwscenario::DiskScenarioError::none;
  const std::size_t cuts[] = {
    0, 3, 0x3B55D, 0x43D4D, 0x48F4D, 0x49A3D,
    0x4D53D, 0x50E45, 0x51365, 0x51E85, 0x52465, 0x5246E
  };
  for (std::size_t i = 0; i < sizeof(cuts) / sizeof(cuts[0]); ++i) {
    require(!gwscenario::parse_disk_scenario_v1(sample.data(), cuts[i],
        output, &error), "truncated input rejected");
    require(output.signature == 0x12345678,
        "failed parse did not publish partial output");
  }

  std::vector<std::uint8_t> legacy(sample);
  legacy[0] = 1;
  legacy[1] = legacy[2] = legacy[3] = 0;
  require(!gwscenario::parse_disk_scenario_v1(legacy.data(), legacy.size(),
      output, &error), "legacy branch rejected");
  require(error == gwscenario::DiskScenarioError::unsupported_legacy_branch,
      "legacy error is explicit");

  std::vector<std::uint8_t> badClass(sample);
  badClass[gwscenario::kPlanetClassFileOffset] = 4;
  require(!gwscenario::parse_disk_scenario_v1(badClass.data(), badClass.size(),
      output, &error), "invalid class rejected");
  require(error == gwscenario::DiskScenarioError::invalid_planet_class,
      "invalid class error is explicit");

  std::vector<std::uint8_t> classD(sample);
  classD[gwscenario::kPlanetClassFileOffset] = 3;
  require(gwscenario::parse_disk_scenario_v1(classD.data(), classD.size(),
      output, &error) && output.b32_letter() == 'd',
      "upper supported class maps to B32D");

  require(!gwscenario::parse_disk_scenario_v1(NULL, 1, output, &error) &&
      error == gwscenario::DiskScenarioError::invalid_argument,
      "null input rejected");
  require(!gwscenario::parse_disk_scenario_v1(sample.data(),
      gwscenario::kMaximumScenarioFileBytes + 1, output, &error) &&
      error == gwscenario::DiskScenarioError::file_too_large,
      "oversize input rejected before access");

  std::vector<std::uint8_t> conditional(sample.begin(),
      sample.begin() + gwscenario::kWirePayloadEnd + 12);
  conditional[gwscenario::kWirePayloadEnd + 5] = 0xBE;
  conditional[gwscenario::kWirePayloadEnd + 6] = 0x06;
  conditional[gwscenario::kWirePayloadEnd + 7] = 0;
  conditional[gwscenario::kWirePayloadEnd + 8] = 0;
  require(!gwscenario::parse_disk_scenario_v1(conditional.data(),
      conditional.size(), output, &error), "conditional tail truncation rejected");
  conditional.push_back(0xA5);
  require(gwscenario::parse_disk_scenario_v1(conditional.data(),
      conditional.size(), output, &error), "complete conditional tail accepted");
  require(output.has_conditional_tail && output.known_tail_bytes == 13,
      "conditional tail length");

  std::uint8_t bytes[] = {0x34, 0x12};
  gwscenario::BoundedReaderV1 reader(bytes, 2);
  std::uint16_t value = 0;
  require(reader.read_u16_le(&value) && value == 0x1234,
      "little-endian word read");
  require(!reader.read_u8(reinterpret_cast<std::uint8_t *>(&value)),
      "bounded reader rejects overrun");
}

} // namespace

int main()
{
  const std::vector<std::uint8_t> sampleA = make_sample(0);
  const std::vector<std::uint8_t> sampleD = make_sample(3);
  check_sample(sampleA, 0);
  check_sample(sampleD, 3);
  check_file_loader(sampleA);
  check_failures(sampleA);
  std::cout << "DISKSCENARIO_V1_SYNTHETIC_TESTS: PASS\n";
  return 0;
}
