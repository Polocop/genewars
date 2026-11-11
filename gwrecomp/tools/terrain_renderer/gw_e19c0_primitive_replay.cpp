#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <iostream>
#include <string>
#include <unordered_map>
#include <vector>

namespace {
constexpr int W = 640, H = 480;
constexpr std::size_t N = static_cast<std::size_t>(W) * H;
struct V { std::int32_t x, y; std::uint32_t u, v, shade; };
struct T { std::uint32_t ordinal, site; V v[3]; };
struct ActualWrite { std::uint32_t ordinal,eip,destination; std::uint8_t value,pad[3]; };
template<class T> bool read_exact(std::ifstream& f,T& x) {
    return static_cast<bool>(f.read(reinterpret_cast<char*>(&x),sizeof x));
}
bool read_bytes(const char* p,std::vector<std::uint8_t>& b) {
    std::ifstream f(p,std::ios::binary|std::ios::ate);
    if(!f) return false;
    const auto n=f.tellg(); if(n<0) return false;
    b.resize(static_cast<std::size_t>(n)); f.seekg(0);
    return b.empty() || static_cast<bool>(f.read(reinterpret_cast<char*>(b.data()),n));
}
std::int64_t edge(const V& a,const V& b,std::int64_t x2,std::int64_t y2) {
    return static_cast<std::int64_t>(2*b.x-2*a.x)*(y2-2*a.y)-
           static_cast<std::int64_t>(2*b.y-2*a.y)*(x2-2*a.x);
}
bool top_left(const V& a,const V& b) {
    const int dx=b.x-a.x,dy=b.y-a.y;
    return dy<0 || (dy==0&&dx>0);
}
void put32(std::ofstream& f,std::uint32_t x) {
    for(unsigned i=0;i<4;i++) f.put(static_cast<char>(x>>(8*i)));
}
void put16(std::ofstream& f,std::uint16_t x) {
    f.put(static_cast<char>(x)); f.put(static_cast<char>(x>>8));
}
bool bmp(const char* p,const std::vector<std::uint8_t>& raw,
         const std::vector<std::uint8_t>& pal) {
    if(raw.size()!=N || pal.size()!=768) return false;
    std::ofstream f(p,std::ios::binary); if(!f) return false;
    const std::uint32_t row=W*3u,bytes=row*H;
    f.put('B');f.put('M');put32(f,54u+bytes);put16(f,0);put16(f,0);put32(f,54);
    put32(f,40);put32(f,W);put32(f,H);put16(f,1);put16(f,24);put32(f,0);
    put32(f,bytes);put32(f,2835);put32(f,2835);put32(f,0);put32(f,0);
    std::vector<char> r(row);
    for(int y=H-1;y>=0;y--) {
        for(int x=0;x<W;x++) {
            const auto c=raw[static_cast<std::size_t>(y)*W+x];
            r[x*3]=static_cast<char>(pal[c*3+2]*255u/63u);
            r[x*3+1]=static_cast<char>(pal[c*3+1]*255u/63u);
            r[x*3+2]=static_cast<char>(pal[c*3]*255u/63u);
        }
        f.write(r.data(),static_cast<std::streamsize>(r.size()));
    }
    return static_cast<bool>(f);
}
}

int main(int argc,char** argv) {
    if(argc!=8) {
        std::cerr<<"usage: gw_e19c0_primitive_replay primitives.bin b32.bin fade.bin original_surface.bin palette6.bin actual_pixel_writes.bin out_prefix\n";
        return 2;
    }
    std::vector<std::uint8_t> tex,fade,reference,pal,actualBytes;
    if(!read_bytes(argv[2],tex)||!read_bytes(argv[3],fade)||
       !read_bytes(argv[4],reference)||!read_bytes(argv[5],pal)||
       !read_bytes(argv[6],actualBytes)||
       tex.size()!=65536||fade.size()!=16384||reference.size()!=N||pal.size()!=768) {
        std::cerr<<"asset size/read failure\n"; return 3;
    }
    std::ifstream f(argv[1],std::ios::binary); if(!f) return 4;
    std::array<char,8> magic{}; f.read(magic.data(),8);
    if(std::memcmp(magic.data(),"GWPRIM1\0",8)!=0) return 5;
    std::uint32_t count=0; if(!read_exact(f,count)||count>4096) return 6;
    std::vector<T> tris(count);
    for(auto& t:tris) {
        if(!read_exact(f,t.ordinal)||!read_exact(f,t.site)) return 7;
        for(auto& v:t.v) {
            std::array<std::uint32_t,5> d{};
            if(!f.read(reinterpret_cast<char*>(d.data()),20)) return 8;
            v={static_cast<std::int32_t>(d[0]),static_cast<std::int32_t>(d[1]),d[2],d[3],d[4]};
        }
    }
    if(actualBytes.size()<12||std::memcmp(actualBytes.data(),"GWPIX1\0\0",8)!=0) return 14;
    std::uint32_t actualCount=0;
    std::memcpy(&actualCount,actualBytes.data()+8,4);
    if(actualBytes.size()!=12u+static_cast<std::size_t>(actualCount)*sizeof(ActualWrite)) return 15;
    std::unordered_map<std::uint64_t,std::uint8_t> actualWrites,predictedWrites;
    actualWrites.reserve(actualCount*2u);
    const auto *actualRows=reinterpret_cast<const ActualWrite*>(actualBytes.data()+12);
    constexpr std::uint32_t surfaceBase=0x021D9CACu;
    for(std::uint32_t i=0;i<actualCount;i++) {
        const auto& w=actualRows[i];
        if(w.destination<surfaceBase||w.destination>=surfaceBase+N) continue;
        const std::uint32_t pixel=w.destination-surfaceBase;
        const std::uint64_t key=(static_cast<std::uint64_t>(w.ordinal)<<32)|pixel;
        actualWrites[key]=w.value;
    }
    std::vector<std::uint8_t> out(N,0),covered(N,0);
    std::vector<std::uint32_t> writes(N,0);
    std::uint64_t candidate=0,clipped=0,invalid_light=0;
    std::uint32_t overdraw=0;
    for(const auto& t:tris) {
        V a=t.v[0],b=t.v[1],c=t.v[2];
        std::int64_t area=edge(a,b,2LL*c.x,2LL*c.y);
        if(!area) continue;
        if(area<0) { std::swap(b,c); area=-area; }
        const int minx=std::max(0,std::min({a.x,b.x,c.x}));
        const int maxx=std::min(W-1,std::max({a.x,b.x,c.x}));
        const int miny=std::max(0,std::min({a.y,b.y,c.y}));
        const int maxy=std::min(H-1,std::max({a.y,b.y,c.y}));
        if(minx>maxx||miny>maxy) continue;
        const bool tl0=top_left(b,c),tl1=top_left(c,a),tl2=top_left(a,b);
        for(int y=miny;y<=maxy;y++) for(int x=minx;x<=maxx;x++) {
            const auto x2=2LL*x+1,y2=2LL*y+1;
            const auto w0=edge(b,c,x2,y2),w1=edge(c,a,x2,y2),w2=edge(a,b,x2,y2);
            if(w0<0||w1<0||w2<0) continue;
            const auto dst=static_cast<std::size_t>(y)*W+x;
            ++candidate;
            if((w0==0&&!tl0)||(w1==0&&!tl1)||(w2==0&&!tl2)) continue;
            const auto u=static_cast<std::uint32_t>((w0*a.u+w1*b.u+w2*c.u)/area);
            const auto v=static_cast<std::uint32_t>((w0*a.v+w1*b.v+w2*c.v)/area);
            const auto sh=static_cast<std::uint32_t>((w0*a.shade+w1*b.shade+w2*c.shade)/area);
            const auto ui=(u>>16)&0xffu,vi=(v>>16)&0xffu;
            const auto light=(sh>>16)&0xffu;
            if(light>=64u) { ++invalid_light; continue; }
            const auto source=(vi<<8)|ui;
            if(source>=tex.size()) { ++clipped; continue; }
            out[dst]=fade[light*256u+tex[source]];
            const std::uint64_t key=(static_cast<std::uint64_t>(t.ordinal)<<32)|dst;
            predictedWrites[key]=out[dst];
            if(writes[dst]++) ++overdraw;
            covered[dst]=1;
        }
    }
    std::uint64_t compared=0,match=0,changed=0,covered_mismatch=0;
    for(std::size_t i=0;i<N;i++) {
        compared++;
        if(out[i]==reference[i]) ++match; else ++changed;
        if(covered[i]&&out[i]!=reference[i]) ++covered_mismatch;
    }
    std::uint64_t write_intersection=0,write_color_match=0,write_predicted_only=0,write_actual_only=0;
    for(const auto& p:predictedWrites) {
        const auto it=actualWrites.find(p.first);
        if(it==actualWrites.end()) ++write_predicted_only;
        else { ++write_intersection; if(it->second==p.second) ++write_color_match; }
    }
    for(const auto& a:actualWrites) if(predictedWrites.find(a.first)==predictedWrites.end()) ++write_actual_only;
    std::string prefix=argv[7];
    { std::ofstream q(prefix+".raw",std::ios::binary); if(!q.write(reinterpret_cast<const char*>(out.data()),out.size())) return 9; }
    { std::ofstream q(prefix+".coverage.raw",std::ios::binary); if(!q.write(reinterpret_cast<const char*>(covered.data()),covered.size())) return 10; }
    if(!bmp((prefix+".bmp").c_str(),out,pal)) return 11;
    std::ofstream j(prefix+".json"); if(!j) return 12;
    j<<"{\n  \"schema\":\"gwrecomp.e19c0-captured-triangle-replay/v1\",\n"
      <<"  \"triangles\":"<<count<<",\n  \"algorithm\":\"affine barycentric, pixel-center samples, top-left fill, U/V and shade 16.16 interpolation, B32 256-byte rows, FADE[light*256+texel]\",\n"
      <<"  \"candidate_triangle_samples\":"<<candidate<<",\n  \"covered_pixels\":"<<std::count(covered.begin(),covered.end(),std::uint8_t{1})<<",\n"
      <<"  \"coverage_gaps_against_original_surface\":"<<N-std::count(covered.begin(),covered.end(),std::uint8_t{1})<<",\n"
      <<"  \"overdraw_pixels\":"<<overdraw<<",\n  \"invalid_light_rows\":"<<invalid_light<<",\n  \"out_of_texture_samples\":"<<clipped<<",\n"
      <<"  \"exact_pixel_matches\":"<<match<<",\n  \"exact_pixel_mismatches\":"<<changed<<",\n"
      <<"  \"match_percent\":"<<(100.0*static_cast<double>(match)/static_cast<double>(compared))<<",\n"
      <<"  \"mismatches_within_covered\":"<<covered_mismatch<<",\n"
      <<"  \"original_pixel_write_events\":"<<actualCount<<",\n  \"original_primitive_pixel_keys\":"<<actualWrites.size()<<",\n"
      <<"  \"predicted_primitive_pixel_keys\":"<<predictedWrites.size()<<",\n  \"same_primitive_pixel_intersection\":"<<write_intersection<<",\n"
      <<"  \"same_primitive_exact_color_matches\":"<<write_color_match<<",\n  \"predicted_only_pixel_keys\":"<<write_predicted_only<<",\n  \"original_only_pixel_keys\":"<<write_actual_only<<",\n"
      <<"  \"reference_surface\":\"observed E41A9 surface capture; pitch 640 established by live destination coordinate (32,32)\",\n"
      <<"  \"qualification\":\"This is a primitive-only modern raster replay, not a validated match to the original rasterizer; any mismatch is retained as evidence and no projection was reconstructed.\"\n}\n";
    std::cout<<"triangles="<<count<<" covered="<<std::count(covered.begin(),covered.end(),std::uint8_t{1})
        <<" match="<<match<<"/"<<compared<<" ("<<(100.0*static_cast<double>(match)/static_cast<double>(compared))
        <<"%), per-primitive pixel intersection="<<write_intersection<<" color_matches="<<write_color_match<<"\n";
    return static_cast<bool>(j)?0:13;
}
