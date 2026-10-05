#ifndef BIO_DISK_SCENARIO_V1_HPP_
#define BIO_DISK_SCENARIO_V1_HPP_

#include <array>
#include <cstddef>
#include <cstdint>
#include <fstream>
#include <new>
#include <string>
#include <utility>
#include <vector>

namespace gwscenario {

static const std::uint32_t kDiskScenarioV1Magic = 0x00055336u;
static const std::size_t kMaximumScenarioFileBytes = 16u * 1024u * 1024u;
static const std::size_t kPlayerCount = 4;
static const std::size_t kPlayerDiskStride = 0x70D;
static const std::size_t kWorldCellCount = 0x4000;
static const std::size_t kWorldCellDiskStride = 0x0E;

static const std::size_t kFamilyACount = 300, kFamilyAWireStride = 0x74, kFamilyARuntimeStride = 0x7C;
static const std::size_t kFamilyBCount = 512, kFamilyBWireStride = 0x29, kFamilyBRuntimeStride = 0x31;
static const std::size_t kFamilyCCount = 20, kFamilyCWireStride = 0x8C, kFamilyCRuntimeStride = 0xC8;
static const std::size_t kFamilyDCount = 256, kFamilyDWireStride = 0x3B, kFamilyDRuntimeStride = 0x43;
static const std::size_t kFamilyECount = 200, kFamilyEWireStride = 0x49, kFamilyERuntimeStride = 0x51;
static const std::size_t kFamilyFCount = 32, kFamilyFWireStride = 0x29, kFamilyFRuntimeStride = 0x31;
static const std::size_t kFamilyGCount = 32, kFamilyGWireStride = 0x59, kFamilyGRuntimeStride = 0x61;
static const std::size_t kFamilyHCount = 16, kFamilyHWireStride = 0x5E, kFamilyHRuntimeStride = 0x66;

static const std::size_t kPlayersOffset = 0x14, kPlayersEnd = 0x1C48;
static const std::size_t kFixedHeaderBegin = 0x1C48, kWorldBegin = 0x355E, kWorldEnd = 0x3B55E;
static const std::size_t kPlanetClassFileOffset = 0x1C5B;
static const std::size_t kPlanetClassFixedHeaderOffset = kPlanetClassFileOffset-kFixedHeaderBegin;
static const std::size_t kFamilyABegin = kWorldEnd;
static const std::size_t kFamilyAEnd = kFamilyABegin+kFamilyACount*kFamilyAWireStride;
static const std::size_t kFamilyBEnd = kFamilyAEnd+kFamilyBCount*kFamilyBWireStride;
static const std::size_t kFamilyCEnd = kFamilyBEnd+kFamilyCCount*kFamilyCWireStride;
static const std::size_t kFamilyDEnd = kFamilyCEnd+kFamilyDCount*kFamilyDWireStride;
static const std::size_t kFamilyEEnd = kFamilyDEnd+kFamilyECount*kFamilyEWireStride;
static const std::size_t kFamilyFEnd = kFamilyEEnd+kFamilyFCount*kFamilyFWireStride;
static const std::size_t kFamilyGEnd = kFamilyFEnd+kFamilyGCount*kFamilyGWireStride;
static const std::size_t kWirePayloadEnd = kFamilyGEnd+kFamilyHCount*kFamilyHWireStride;
static const std::size_t kTailPrefixBytes = 9, kConditionalTailValue = 0x6BE;
static const std::size_t kConditionalTailBytes = 4;
static const std::size_t kMaximumKnownTailBytes = kTailPrefixBytes+kConditionalTailBytes;

static_assert(4+0x10==kPlayersOffset, "player disk start");
static_assert(kPlayersOffset+kPlayerCount*kPlayerDiskStride==kPlayersEnd, "player disk range");
static_assert(kPlayersEnd+0x1916==kWorldBegin, "fixed header disk range");
static_assert(kWorldBegin+kWorldCellCount*kWorldCellDiskStride==kWorldEnd, "world disk range");
static_assert(kPlanetClassFixedHeaderOffset==0x13, "planetClass disk offset");
static_assert(kWirePayloadEnd==0x52466, "GW 1.0 serialized family cursor");
static_assert(kFamilyAEnd==0x43D4E && kFamilyBEnd==0x48F4E && kFamilyCEnd==0x49A3E, "family A-C ranges");
static_assert(kFamilyDEnd==0x4D53E && kFamilyEEnd==0x50E46 && kFamilyFEnd==0x51366 && kFamilyGEnd==0x51E86, "family D-G ranges");

struct DiskPlayerV1 { std::array<std::uint8_t,kPlayerDiskStride> bytes; };
struct DiskWorldCellV1 {
  std::array<std::uint8_t,kWorldCellDiskStride> bytes;
  std::uint8_t byte_0C() const { return bytes[0x0C]; }
};
template <std::size_t W,std::size_t R> struct DiskRecordV1 {
  static const std::size_t wire_stride=W, runtime_stride=R;
  std::array<std::uint8_t,W> bytes;
};
typedef DiskRecordV1<kFamilyAWireStride,kFamilyARuntimeStride> DiskRecordA;
typedef DiskRecordV1<kFamilyBWireStride,kFamilyBRuntimeStride> DiskRecordB;
typedef DiskRecordV1<kFamilyCWireStride,kFamilyCRuntimeStride> DiskRecordC;
typedef DiskRecordV1<kFamilyDWireStride,kFamilyDRuntimeStride> DiskRecordD;
typedef DiskRecordV1<kFamilyEWireStride,kFamilyERuntimeStride> DiskRecordE;
typedef DiskRecordV1<kFamilyFWireStride,kFamilyFRuntimeStride> DiskRecordF;
typedef DiskRecordV1<kFamilyGWireStride,kFamilyGRuntimeStride> DiskRecordG;
typedef DiskRecordV1<kFamilyHWireStride,kFamilyHRuntimeStride> DiskRecordH;

struct DiskRangeV1 {
  std::size_t begin,end;
  DiskRangeV1():begin(0),end(0){}
  std::size_t size() const { return end-begin; }
};
enum class DiskScenarioError { none,invalid_argument,truncated,unsupported_legacy_branch,invalid_planet_class,file_too_large,io_error };
inline const char *disk_scenario_error_name(DiskScenarioError e) {
  switch(e) {
  case DiskScenarioError::none:return "none";
  case DiskScenarioError::invalid_argument:return "invalid_argument";
  case DiskScenarioError::truncated:return "truncated";
  case DiskScenarioError::unsupported_legacy_branch:return "unsupported_legacy_branch";
  case DiskScenarioError::invalid_planet_class:return "invalid_planet_class";
  case DiskScenarioError::file_too_large:return "file_too_large";
  case DiskScenarioError::io_error:return "io_error";
  }
  return "unknown";
}

class BoundedReaderV1 {
public:
  BoundedReaderV1(const std::uint8_t *p,std::size_t n):data_(p),size_(n),pos_(0){}
  bool read_exact(std::uint8_t *dst,std::size_t n) {
    if(n>remaining()||(n&&(data_==NULL||dst==NULL)))return false;
    for(std::size_t i=0;i<n;++i)dst[i]=data_[pos_+i];
    pos_+=n; return true;
  }
  bool read_u8(std::uint8_t *v){return v&&read_exact(v,1);}
  bool read_u16_le(std::uint16_t *v) {
    std::uint8_t b[2]; if(!v||!read_exact(b,2))return false;
    *v=static_cast<std::uint16_t>(b[0])|(static_cast<std::uint16_t>(b[1])<<8); return true;
  }
  bool read_u32_le(std::uint32_t *v) {
    std::uint8_t b[4]; if(!v||!read_exact(b,4))return false;
    *v=static_cast<std::uint32_t>(b[0])|(static_cast<std::uint32_t>(b[1])<<8)|
      (static_cast<std::uint32_t>(b[2])<<16)|(static_cast<std::uint32_t>(b[3])<<24); return true;
  }
  bool skip(std::size_t n){if(n>remaining())return false;pos_+=n;return true;}
  std::size_t position()const{return pos_;}
  std::size_t size()const{return size_;}
  std::size_t remaining()const{return size_-pos_;}
private:
  const std::uint8_t *data_; std::size_t size_,pos_;
};

struct DiskScenarioV1 {
  std::uint32_t signature;
  std::array<std::uint8_t,0x10> prefix_before_players;
  std::array<DiskPlayerV1,kPlayerCount> players;
  std::array<std::uint8_t,0x1916> fixed_header_bytes;
  std::vector<DiskWorldCellV1> world;
  std::vector<DiskRecordA> family_A; std::vector<DiskRecordB> family_B;
  std::vector<DiskRecordC> family_C; std::vector<DiskRecordD> family_D;
  std::vector<DiskRecordE> family_E; std::vector<DiskRecordF> family_F;
  std::vector<DiskRecordG> family_G; std::vector<DiskRecordH> family_H;
  std::array<DiskRangeV1,8> family_ranges;
  std::size_t source_file_size,tail_begin,known_tail_bytes;
  std::array<std::uint8_t,kTailPrefixBytes> tail_prefix_bytes;
  std::array<std::uint8_t,kConditionalTailBytes> conditional_tail_bytes;
  bool has_conditional_tail;
  std::vector<std::uint8_t> opaque_tail_bytes;
  std::uint8_t planetClass;
  DiskScenarioV1():signature(0),source_file_size(0),tail_begin(0),known_tail_bytes(0),has_conditional_tail(false),planetClass(0){}
  char b32_letter()const{return static_cast<char>('a'+planetClass);}
  std::string b32_filename()const{std::string n("data\\b32a.dat");n[8]=b32_letter();return n;}
  std::size_t parsed_cursor()const{return tail_begin+known_tail_bytes;}
  std::size_t trailing_opaque_size()const{return source_file_size-parsed_cursor();}
};

template<typename R> inline bool read_record_family_v1(BoundedReaderV1 &reader,std::size_t count,std::vector<R>&records) {
  records.resize(count);
  for(std::size_t i=0;i<count;++i)if(!reader.read_exact(records[i].bytes.data(),R::wire_stride))return false;
  return true;
}
inline void set_disk_scenario_error(DiskScenarioError v,DiskScenarioError *e){if(e)*e=v;}

inline bool parse_disk_scenario_v1(const std::uint8_t *data,std::size_t size,DiskScenarioV1 &output,DiskScenarioError *error=NULL) {
  set_disk_scenario_error(DiskScenarioError::none,error);
  if(!data){set_disk_scenario_error(DiskScenarioError::invalid_argument,error);return false;}
  if(size>kMaximumScenarioFileBytes){set_disk_scenario_error(DiskScenarioError::file_too_large,error);return false;}
  if(size<4){set_disk_scenario_error(DiskScenarioError::truncated,error);return false;}
  try {
    DiskScenarioV1 parsed; BoundedReaderV1 reader(data,size);
    if(!reader.read_u32_le(&parsed.signature)){set_disk_scenario_error(DiskScenarioError::truncated,error);return false;}
    if(parsed.signature!=0x00055336u){set_disk_scenario_error(DiskScenarioError::unsupported_legacy_branch,error);return false;}
    if(size<kWirePayloadEnd+kTailPrefixBytes){set_disk_scenario_error(DiskScenarioError::truncated,error);return false;}
    parsed.source_file_size=size;
    if(!reader.read_exact(parsed.prefix_before_players.data(),parsed.prefix_before_players.size())){set_disk_scenario_error(DiskScenarioError::truncated,error);return false;}
    for(std::size_t i=0;i<parsed.players.size();++i)
      if(!reader.read_exact(parsed.players[i].bytes.data(),parsed.players[i].bytes.size())){set_disk_scenario_error(DiskScenarioError::truncated,error);return false;}
    if(!reader.read_exact(parsed.fixed_header_bytes.data(),parsed.fixed_header_bytes.size())){set_disk_scenario_error(DiskScenarioError::truncated,error);return false;}
    parsed.planetClass=parsed.fixed_header_bytes[kPlanetClassFixedHeaderOffset];
    if(parsed.planetClass>3){set_disk_scenario_error(DiskScenarioError::invalid_planet_class,error);return false;}
    parsed.world.resize(kWorldCellCount);
    for(std::size_t i=0;i<parsed.world.size();++i)
      if(!reader.read_exact(parsed.world[i].bytes.data(),parsed.world[i].bytes.size())){set_disk_scenario_error(DiskScenarioError::truncated,error);return false;}
    if(reader.position()!=kWorldEnd){set_disk_scenario_error(DiskScenarioError::invalid_argument,error);return false;}

    parsed.family_ranges[0].begin=reader.position();
    if(!read_record_family_v1(reader,kFamilyACount,parsed.family_A)){set_disk_scenario_error(DiskScenarioError::truncated,error);return false;}
    parsed.family_ranges[0].end=reader.position(); parsed.family_ranges[1].begin=reader.position();
    if(!read_record_family_v1(reader,kFamilyBCount,parsed.family_B)){set_disk_scenario_error(DiskScenarioError::truncated,error);return false;}
    parsed.family_ranges[1].end=reader.position(); parsed.family_ranges[2].begin=reader.position();
    if(!read_record_family_v1(reader,kFamilyCCount,parsed.family_C)){set_disk_scenario_error(DiskScenarioError::truncated,error);return false;}
    parsed.family_ranges[2].end=reader.position(); parsed.family_ranges[3].begin=reader.position();
    if(!read_record_family_v1(reader,kFamilyDCount,parsed.family_D)){set_disk_scenario_error(DiskScenarioError::truncated,error);return false;}
    parsed.family_ranges[3].end=reader.position(); parsed.family_ranges[4].begin=reader.position();
    if(!read_record_family_v1(reader,kFamilyECount,parsed.family_E)){set_disk_scenario_error(DiskScenarioError::truncated,error);return false;}
    parsed.family_ranges[4].end=reader.position(); parsed.family_ranges[5].begin=reader.position();
    if(!read_record_family_v1(reader,kFamilyFCount,parsed.family_F)){set_disk_scenario_error(DiskScenarioError::truncated,error);return false;}
    parsed.family_ranges[5].end=reader.position(); parsed.family_ranges[6].begin=reader.position();
    if(!read_record_family_v1(reader,kFamilyGCount,parsed.family_G)){set_disk_scenario_error(DiskScenarioError::truncated,error);return false;}
    parsed.family_ranges[6].end=reader.position(); parsed.family_ranges[7].begin=reader.position();
    if(!read_record_family_v1(reader,kFamilyHCount,parsed.family_H)){set_disk_scenario_error(DiskScenarioError::truncated,error);return false;}
    parsed.family_ranges[7].end=reader.position();
    if(reader.position()!=kWirePayloadEnd){set_disk_scenario_error(DiskScenarioError::invalid_argument,error);return false;}
    parsed.tail_begin=reader.position();
    if(!reader.read_exact(parsed.tail_prefix_bytes.data(),parsed.tail_prefix_bytes.size())){set_disk_scenario_error(DiskScenarioError::truncated,error);return false;}
    const std::uint32_t conditional_value=static_cast<std::uint32_t>(parsed.tail_prefix_bytes[5])|
      (static_cast<std::uint32_t>(parsed.tail_prefix_bytes[6])<<8)|
      (static_cast<std::uint32_t>(parsed.tail_prefix_bytes[7])<<16)|
      (static_cast<std::uint32_t>(parsed.tail_prefix_bytes[8])<<24);
    if(conditional_value==kConditionalTailValue){
      parsed.has_conditional_tail=true;
      if(!reader.read_exact(parsed.conditional_tail_bytes.data(),parsed.conditional_tail_bytes.size())){set_disk_scenario_error(DiskScenarioError::truncated,error);return false;}
      parsed.known_tail_bytes=kMaximumKnownTailBytes;
    }else parsed.known_tail_bytes=kTailPrefixBytes;
    parsed.opaque_tail_bytes.assign(data+parsed.tail_begin,data+size);
    output=std::move(parsed); set_disk_scenario_error(DiskScenarioError::none,error); return true;
  }catch(const std::bad_alloc&){set_disk_scenario_error(DiskScenarioError::file_too_large,error);return false;}
}

inline bool parse_disk_scenario_v1_file(const std::string &path,DiskScenarioV1 &output,DiskScenarioError *error=NULL) {
  std::ifstream file(path.c_str(),std::ios::binary|std::ios::ate);
  if(!file){set_disk_scenario_error(DiskScenarioError::io_error,error);return false;}
  const std::ifstream::pos_type end=file.tellg();
  if(end<std::ifstream::pos_type(0)){set_disk_scenario_error(DiskScenarioError::io_error,error);return false;}
  const std::streamoff length=static_cast<std::streamoff>(end);
  if(length<0||static_cast<unsigned long long>(length)>kMaximumScenarioFileBytes){set_disk_scenario_error(DiskScenarioError::file_too_large,error);return false;}
  try {
    std::vector<std::uint8_t> bytes(static_cast<std::size_t>(length)); file.seekg(0,std::ios::beg);
    if(!file || (length!=0 && !file.read(reinterpret_cast<char*>(bytes.data()),static_cast<std::streamsize>(length)))){set_disk_scenario_error(DiskScenarioError::io_error,error);return false;}
    return parse_disk_scenario_v1(bytes.data(),bytes.size(),output,error);
  }catch(const std::bad_alloc&){set_disk_scenario_error(DiskScenarioError::file_too_large,error);return false;}
}

} // namespace gwscenario

#endif // BIO_DISK_SCENARIO_V1_HPP_
