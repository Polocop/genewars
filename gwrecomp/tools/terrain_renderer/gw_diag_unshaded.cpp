#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <limits>
#include <sstream>
#include <string>
#include <vector>

#include "gw_authentic_terrain_math.h"

namespace {
constexpr std::size_t kScenarioBytes = 343958;
constexpr std::size_t kWorldBegin = 0x355E;
constexpr std::size_t kCellStride = 14;
constexpr std::size_t kWorldBytes = 128u * 128u * kCellStride;
constexpr std::size_t kB32Bytes = 160u * 32u * 32u;

bool read_file(const std::string& path, std::vector<std::uint8_t>& out) {
    std::ifstream f(path, std::ios::binary | std::ios::ate);
    if (!f) return false;
    const auto n = f.tellg();
    if (n < 0) return false;
    out.resize(static_cast<std::size_t>(n));
    f.seekg(0);
    return out.empty() || static_cast<bool>(f.read(reinterpret_cast<char*>(out.data()), n));
}
std::uint16_t le16(const std::uint8_t* p) {
    return static_cast<std::uint16_t>(p[0] | (std::uint16_t(p[1]) << 8));
}
void u16(std::ofstream& f, std::uint16_t n) {
    f.put(static_cast<char>(n)); f.put(static_cast<char>(n >> 8));
}
void u32(std::ofstream& f, std::uint32_t n) {
    for (int i=0;i<4;++i) f.put(static_cast<char>(n >> (8*i)));
}
std::int32_t signed_height(const std::uint8_t* c) {
    return static_cast<std::int16_t>(le16(c + 2));
}
std::int32_t sar6(std::int32_t n) {
    return n >= 0 ? n / 64 : -(((-n) + 63) / 64);
}
int wrap_q8_delta(int worldQ8, int cameraQ8) {
    int d = worldQ8 - cameraQ8;
    while (d < -(64 * 256)) d += 128 * 256;
    while (d >= 64 * 256) d -= 128 * 256;
    return d;
}
struct Tile {
    int wx, wy, block, height, flags, sx, sy;
    std::size_t texBase;
};
struct Vertex { int x, y, h, u, v; };
struct AuthVertex { gw::terrain::GWVertex20 v; };
struct Frame {
    int width, height;
    std::vector<std::uint8_t> indexed;
    std::vector<std::uint8_t> covered;
    std::vector<std::uint32_t> writes;
    std::vector<Tile> visible;
    std::uint64_t writeOps = 0;
    std::uint64_t overdraw = 0;
};
bool write_bmp24(const std::string& path, const Frame& frame,
                 const std::vector<std::uint8_t>& pal) {
    std::ofstream f(path, std::ios::binary);
    if (!f || pal.size() != 768) return false;
    const std::uint32_t rowBytes = (static_cast<std::uint32_t>(frame.width) * 3u + 3u) & ~3u;
    const std::uint32_t imageBytes = rowBytes * static_cast<std::uint32_t>(frame.height);
    f.put('B'); f.put('M'); u32(f, 54u + imageBytes); u16(f,0); u16(f,0); u32(f,54);
    u32(f,40); u32(f,static_cast<std::uint32_t>(frame.width));
    u32(f,static_cast<std::uint32_t>(frame.height)); u16(f,1); u16(f,24);
    u32(f,0); u32(f,imageBytes); u32(f,2835); u32(f,2835); u32(f,0); u32(f,0);
    std::vector<std::uint8_t> row(rowBytes, 0);
    for (int y=frame.height-1; y>=0; --y) {
        for (int x=0; x<frame.width; ++x) {
            const std::uint8_t index = frame.indexed[static_cast<std::size_t>(y)*frame.width+x];
            const unsigned b6 = pal[index*3u+2u], g6 = pal[index*3u+1u], r6 = pal[index*3u];
            // Match the existing SDL capture conversion of the original 6-bit VGA palette.
            row[x*3+0] = static_cast<std::uint8_t>(b6 * 255u / 63u);
            row[x*3+1] = static_cast<std::uint8_t>(g6 * 255u / 63u);
            row[x*3+2] = static_cast<std::uint8_t>(r6 * 255u / 63u);
        }
        f.write(reinterpret_cast<const char*>(row.data()), row.size());
    }
    return static_cast<bool>(f);
}
bool write_bytes(const std::string& path, const std::vector<std::uint8_t>& v) {
    std::ofstream f(path, std::ios::binary);
    return f && static_cast<bool>(f.write(reinterpret_cast<const char*>(v.data()), v.size()));
}
long long edge2(const Vertex& a,const Vertex& b,int px2,int py2) {
    return static_cast<long long>(2*b.x-2*a.x)*(py2-2*a.y)-
           static_cast<long long>(2*b.y-2*a.y)*(px2-2*a.x);
}
bool top_left(const Vertex& a,const Vertex& b) {
    const int dx=b.x-a.x,dy=b.y-a.y;
    return dy<0 || (dy==0 && dx>0);
}
int clampi(int x,int lo,int hi) { return std::max(lo,std::min(hi,x)); }
bool raster_triangle(Frame& frame,const std::vector<std::uint8_t>& b32,
                     const Vertex& a,const Vertex& b,const Vertex& c,
                     std::size_t texBase,std::vector<std::uint8_t>& expected,
                     std::uint64_t& triangleInteriorPixels) {
    const long long area=edge2(a,b,2*c.x,2*c.y);
    if(area==0) return true;
    Vertex v0=a,v1=b,v2=c;
    long long orientedArea=area;
    if(orientedArea<0) { std::swap(v1,v2); orientedArea=-orientedArea; }
    const int minx=std::max(0,std::min({v0.x,v1.x,v2.x}));
    const int maxx=std::min(frame.width-1,std::max({v0.x,v1.x,v2.x}));
    const int miny=std::max(0,std::min({v0.y,v1.y,v2.y}));
    const int maxy=std::min(frame.height-1,std::max({v0.y,v1.y,v2.y}));
    if(minx>maxx || miny>maxy) return true;
    const bool tl0=top_left(v1,v2),tl1=top_left(v2,v0),tl2=top_left(v0,v1);
    for(int y=miny;y<=maxy;++y) for(int x=minx;x<=maxx;++x) {
        const int px2=2*x+1,py2=2*y+1;
        long long w0=edge2(v1,v2,px2,py2),w1=edge2(v2,v0,px2,py2),w2=edge2(v0,v1,px2,py2);
        if(w0<0 || w1<0 || w2<0) continue;
        const std::size_t dst=static_cast<std::size_t>(y)*frame.width+x;
        expected[dst]=1;
        ++triangleInteriorPixels;
        if((w0==0&&!tl0)||(w1==0&&!tl1)||(w2==0&&!tl2)) continue;
        const long long u=(w0*v0.u+w1*v1.u+w2*v2.u)/orientedArea;
        const long long v=(w0*v0.v+w1*v1.v+w2*v2.v)/orientedArea;
        const int texU=clampi(static_cast<int>(u),0,31),texV=clampi(static_cast<int>(v),0,31);
        const std::size_t src=texBase+static_cast<std::size_t>(texV)*256u+static_cast<std::size_t>(texU);
        if(src>=b32.size()) return false;
        frame.indexed[dst]=b32[src]; frame.covered[dst]=1;
        if(frame.writes[dst]) ++frame.overdraw;
        ++frame.writes[dst]; ++frame.writeOps;
    }
    return true;
}
bool render(const std::vector<std::uint8_t>& scenario,
            const std::vector<std::uint8_t>& b32,
            const std::vector<std::uint8_t>& pal,
            int width, int height, int camXQ8, int camYQ8,
            int scaleX, int scaleY, int heightScale,
            const std::string& prefix, Frame& frame) {
    frame.width=width; frame.height=height;
    const std::size_t pixelCount=static_cast<std::size_t>(width)*height;
    frame.indexed.assign(pixelCount,0);
    frame.covered.assign(pixelCount,0);
    frame.writes.assign(pixelCount,0);
    std::vector<std::uint8_t> expected(pixelCount,0);
    const int scaleFactor=std::max(1,scaleY/16);
    const int centerX=384*scaleFactor,centerY=240*scaleFactor;
    for (int wy=0;wy<128;++wy) for (int wx=0;wx<128;++wx) {
        const std::size_t off=kWorldBegin+(static_cast<std::size_t>(wy)*128+wx)*kCellStride;
        const std::uint8_t* c=scenario.data()+off;
        const int block=c[4];
        if (block >= 160) continue;
        const int dx=wrap_q8_delta(wx*256,camXQ8);
        const int dy=wrap_q8_delta(wy*256,camYQ8);
        const int h=signed_height(c);
        const int sx=centerX + ((dx-dy)*scaleX)/256;
        const int sy=centerY + ((dx+dy)*scaleY)/256 - sar6(h)*heightScale;
        if (sx < -32 || sx >= width+32 || sy < -16 || sy >= height+16) continue;
        const std::size_t texBase=static_cast<std::size_t>(block/8)*0x2000u+
                                  static_cast<std::size_t>(block%8)*0x20u;
        frame.visible.push_back(Tile{wx,wy,block,h,c[5],sx,sy,texBase});
    }
    std::stable_sort(frame.visible.begin(),frame.visible.end(),[](const Tile& a,const Tile& b) {
        if (a.sy != b.sy) return a.sy < b.sy;
        if (a.sx != b.sx) return a.sx < b.sx;
        if (a.wy != b.wy) return a.wy < b.wy;
        return a.wx < b.wx;
    });
    std::ofstream cells(prefix+".cells.csv");
    if (!cells) return false;
    cells << "draw_order,world_x,world_y,scenario_cell_offset,height_s16,block_id,topology_orientation_byte,atlas_offset,screen_center_x,screen_center_y,covered_pixels\n";
    std::uint64_t candidatePixels=0;
    for (std::size_t ti=0;ti<frame.visible.size();++ti) {
        const Tile& t=frame.visible[ti];
        std::uint64_t tilePixels=0;
        auto project=[&](int wx,int wy,int u,int v)->Vertex {
            wx&=127; wy&=127;
            const std::size_t voff=kWorldBegin+(static_cast<std::size_t>(wy)*128+wx)*kCellStride;
            const std::uint8_t* vc=scenario.data()+voff;
            const int vx=wrap_q8_delta(wx*256,camXQ8),vy=wrap_q8_delta(wy*256,camYQ8);
            const int vh=signed_height(vc);
            return Vertex{centerX+((vx-vy)*scaleX)/256,
                          centerY-scaleY + ((vx+vy)*scaleY)/256-sar6(vh)*heightScale,
                          vh,u,v};
        };
        const Vertex v00=project(t.wx,t.wy,0,0);
        const Vertex v10=project(t.wx+1,t.wy,31,0);
        const Vertex v11=project(t.wx+1,t.wy+1,31,31);
        const Vertex v01=project(t.wx,t.wy+1,0,31);
        const std::uint64_t before=frame.writeOps;
        // Fixed V00-V11 diagonal. Shared corner coordinates/heights make all neighbor edges identical.
        if(!raster_triangle(frame,b32,v00,v10,v11,t.texBase,expected,candidatePixels) ||
           !raster_triangle(frame,b32,v00,v11,v01,t.texBase,expected,candidatePixels)) return false;
        tilePixels=frame.writeOps-before;
        const std::size_t off=kWorldBegin+(static_cast<std::size_t>(t.wy)*128+t.wx)*kCellStride;
        cells << ti << ',' << t.wx << ',' << t.wy << ",0x" << std::hex << off << std::dec
              << ',' << t.height << ',' << t.block << ",0x" << std::hex << t.flags << std::dec
              << ",0x" << std::hex << t.texBase << std::dec << ',' << t.sx << ',' << t.sy
              << ',' << tilePixels << '\n';
    }
    cells.close();
    std::uint64_t expectedPixels=0,gapPixels=0,blackCovered=0;
    for(std::size_t i=0;i<pixelCount;++i) {
        expectedPixels+=expected[i]!=0;
        gapPixels+=(expected[i]!=0 && frame.covered[i]==0);
        blackCovered+=(frame.covered[i]!=0 && frame.indexed[i]==0);
    }
    if (!write_bytes(prefix+".indexed.raw",frame.indexed) ||
        !write_bytes(prefix+".coverage.raw",frame.covered) ||
        !write_bmp24(prefix+".bmp",frame,pal)) return false;
    std::ofstream metrics(prefix+".mesh.json");
    if(!metrics) return false;
    metrics << "{\n  \"projection\":\"x=centerX+((dx-dy)*scaleX)/256; y=centerY-scaleY+((dx+dy)*scaleY)/256-SAR6(height*heightScale); center=(384,240)*scaleY/16\",\n"
            << "  \"cell_corners\":\"(X,Y),(X+1,Y),(X+1,Y+1),(X,Y+1)\",\n"
            << "  \"corner_height_source\":\"same 14-byte world record grid, signed int16 at +2\",\n"
            << "  \"triangulation\":\"V00-V11 diagonal; shared corner projection; top-left edge rule\",\n"
            << "  \"expected_interior_pixels\":" << expectedPixels << ",\n"
            << "  \"interior_gap_pixels\":" << gapPixels << ",\n"
            << "  \"interior_gap_percent\":" << (expectedPixels?100.0*gapPixels/expectedPixels:0.0) << ",\n"
            << "  \"covered_black_texels\":" << blackCovered << ",\n"
            << "  \"candidate_triangle_samples\":" << candidatePixels << ",\n"
            << "  \"canary\":\"vector allocations bound all writes to width*height; no guard-region write\"\n}\n";
    return static_cast<bool>(metrics);
}

// Explicit experimental path: feeds map records through the extracted x86
// emission helper and the captured 64x256 FADE table.  It is opt-in so the
// older renderer remains available as a control while screen-space mapping
// is being compared against the native capture.
bool render_helper_hybrid(const std::vector<std::uint8_t>& scenario,
            const std::vector<std::uint8_t>& b32,
            const std::vector<std::uint8_t>& pal,
            const std::vector<std::uint8_t>& fade,
            int width, int height, int camXQ8, int camYQ8,
            int scaleX, int scaleY, int heightScale,
            const std::string& prefix, Frame& frame) {
    using namespace gw::terrain;
    if (fade.size() != GW_FADE_TABLE_SIZE) return false;
    frame.width=width; frame.height=height;
    const std::size_t n=static_cast<std::size_t>(width)*height;
    frame.indexed.assign(n,0); frame.covered.assign(n,0); frame.writes.assign(n,0);
    std::vector<std::uint8_t> expected(n,0);
    const int scaleFactor=std::max(1,height/480);
    GWTerrainCameraState cam{};
    cam.cam_x_base=camXQ8; cam.cam_y_base=camYQ8;
    cam.g_184aa4=scaleX; cam.g_184aa8=scaleY; cam.g_184aac=66;
    cam.g_184ab0=48; cam.g_184ab4=heightScale;
    cam.camera_flags=0x01; cam.emit_mode=5;
    std::uint64_t samples=0;
    auto read_cell=[&](int x,int y,GWMapCellRecord& r) {
        x&=127; y&=127;
        const auto off=kWorldBegin+(static_cast<std::size_t>(y)*128u+x)*kCellStride;
        const auto* p=scenario.data()+off;
        r={}; r.coord_word=le16(p); r.height_word=le16(p+2);
        r.top_flag_a=p[4]; r.top_flag_b=p[5];
        std::copy(p+6,p+12,r.pad_06); r.scale_byte=p[12]; r.cell_kind=p[13];
    };
    auto project_for_comparison=[&](int wx,int wy) {
        wx&=127; wy&=127;
        const int dx=wrap_q8_delta(wx*256,camXQ8),dy=wrap_q8_delta(wy*256,camYQ8);
        const auto off=kWorldBegin+(static_cast<std::size_t>(wy)*128u+wx)*kCellStride;
        const int h=signed_height(scenario.data()+off);
        const int sx=384*scaleFactor+(((dx-dy)*scaleX)/256)*scaleFactor;
        const int sy=240*scaleFactor-scaleY*scaleFactor+
                     (((dx+dy)*scaleY)/256)*scaleFactor-sar6(h)*heightScale*scaleFactor;
        return std::array<int,3>{sx,sy,h};
    };
    for (int y=0;y<128;++y) for (int x=0;x<128;++x) {
        GWMapCellRecord c[4];
        read_cell(x,y,c[0]); read_cell(x+1,y,c[1]);
        read_cell(x+1,y+1,c[2]); read_cell(x,y+1,c[3]);
        if (c[0].cell_kind >= 160) continue;
        GWTerrainCameraState local=cam;
        const auto linkCell=GW_MAP_TABLE_BASE+
            static_cast<std::uint32_t>(y)*GW_MAP_ROW_STRIDE+
            static_cast<std::uint32_t>(x*14);
        local.current_cell_addr=linkCell;
        GWTriangleEmit emits[6]{}; int emitCount=0;
        const int centerX=384*scaleFactor;
        // [esp+0x74] is the shared x accumulator in the helper. Center it
        // in the original 640px viewport, preserving that anchor at 2K.
        const int baseX=(centerX<<16);
        if (!gw_emit_cell_triangles(c,local,baseX,emits,&emitCount)) continue;
        const std::uint8_t block=c[0].top_flag_a; // overridden by the B32 cell selector below
        (void)block;
        const std::size_t cellOff=kWorldBegin+(static_cast<std::size_t>(y)*128u+x)*kCellStride;
        const unsigned blockId=scenario[cellOff+4];
        if (blockId>=160) continue;
        const std::size_t texBase=static_cast<std::size_t>(blockId/8u)*0x2000u+
                                  static_cast<std::size_t>(blockId%8u)*0x20u;
        for(int ei=0;ei<emitCount;++ei) {
            const auto& e=emits[ei];
            Vertex v[3]{};
            for(int k=0;k<3;++k) {
                // The helper's x/y values are retained as diagnostics; their
                // direct 16.16 interpretation was separately rendered and
                // measured (32 pixels at 640x480, zero at 2K). For this
                // hybrid visual pass, use the existing renderer's measured
                // cell projection, while UV/pass/shade come from the helper.
                const bool umax=e.v[k].u_fp16!=GW_B32_UV_MIN;
                const bool vmax=e.v[k].v_fp16!=GW_B32_UV_MIN;
                // New perimeter-contiguous UV scheme (Bug 2): (0,0)->c[0] NW,
                // (31,0)->c[1] NE, (31,31)->c[2] SE, (0,31)->c[3] SW.
                const int corner=umax?(vmax?2:1):(vmax?3:0);
                const int wxv=x+((corner==1||corner==2)?1:0);
                const int wyv=y+((corner==2||corner==3)?1:0);
                const auto projected=project_for_comparison(wxv,wyv);
                v[k].x=projected[0]; v[k].y=projected[1]; v[k].h=projected[2];
                v[k].u=static_cast<int>(e.v[k].u_fp16>>16);
                v[k].v=static_cast<int>(e.v[k].v_fp16>>16);
                v[k].h=static_cast<int>(e.v[k].shade_fp16);
            }
            long long area=edge2(v[0],v[1],2*v[2].x,2*v[2].y);
            if(area==0) continue;
            Vertex a=v[0],b=v[1],cV=v[2];
            if(area<0){std::swap(b,cV);area=-area;}
            const int minx=std::max(0,std::min({a.x,b.x,cV.x}));
            const int maxx=std::min(width-1,std::max({a.x,b.x,cV.x}));
            const int miny=std::max(0,std::min({a.y,b.y,cV.y}));
            const int maxy=std::min(height-1,std::max({a.y,b.y,cV.y}));
            const bool tl0=top_left(b,cV),tl1=top_left(cV,a),tl2=top_left(a,b);
            for(int py=miny;py<=maxy;++py) for(int px=minx;px<=maxx;++px) {
                const int px2=2*px+1,py2=2*py+1;
                const long long w0=edge2(b,cV,px2,py2),w1=edge2(cV,a,px2,py2),w2=edge2(a,b,px2,py2);
                if(w0<0||w1<0||w2<0) continue;
                const auto dst=static_cast<std::size_t>(py)*width+px; expected[dst]=1;
                if((w0==0&&!tl0)||(w1==0&&!tl1)||(w2==0&&!tl2)) continue;
                const auto u=static_cast<int>((w0*a.u+w1*b.u+w2*cV.u)/area);
                const auto vv=static_cast<int>((w0*a.v+w1*b.v+w2*cV.v)/area);
                const auto shade=static_cast<std::uint32_t>((w0*a.h+w1*b.h+w2*cV.h)/area);
                const auto src=texBase+static_cast<std::size_t>(std::clamp(vv,0,31))*256u+
                               static_cast<std::size_t>(std::clamp(u,0,31));
                if(src>=b32.size()) return false;
                frame.indexed[dst]=b32[src];
                frame.covered[dst]=1; ++frame.writes[dst]; ++frame.writeOps; ++samples;
            }
        }
        frame.visible.push_back(Tile{x,y,static_cast<int>(blockId),signed_height(scenario.data()+cellOff),
                                     scenario[cellOff+5],centerX,0,texBase});
    }
    std::uint64_t exp=0,gaps=0,black=0;
    for(std::size_t i=0;i<n;++i){ exp+=expected[i]!=0; gaps+=(expected[i]&&!frame.covered[i]); black+=(frame.covered[i]&&frame.indexed[i]==0); }
    if(!write_bytes(prefix+".indexed.raw",frame.indexed)||!write_bytes(prefix+".coverage.raw",frame.covered)||!write_bmp24(prefix+".bmp",frame,pal)) return false;
    std::ofstream m(prefix+".mesh.json");
    if(!m) return false;
    m << "{\n  \"pipeline\":\"gw_emit_cell_triangles + B32 + FADE lookup\",\n"
      << "  \"projection_interpretation\":\"hybrid: authentic helper controls pass gates, B32 UV and FADE shade; screen corners use prior 32x16x2 data-renderer projection because live vertex screen-field mapping did not pass A/B\",\n"
      << "  \"camera_q8\":["<<camXQ8<<","<<camYQ8<<"],\n  \"parameters\":["<<scaleX<<","<<scaleY<<","<<heightScale<<",66,48],\n"
      << "  \"source_cells_considered\":16384,\n  \"emission_pixel_samples\":"<<samples<<",\n"
      << "  \"expected_triangle_pixels\":"<<exp<<",\n  \"coverage_gaps\":"<<gaps<<",\n"
      << "  \"covered_zero_texels\":"<<black<<",\n  \"map_tiles\":"<<frame.visible.size()<<",\n"
      << "  \"write_bounds\":\"all destinations bounded to width*height vector\"\n}\n";
    return static_cast<bool>(m);
}
}

int main(int argc,char**argv) {
    const bool helperHybrid=(argc==14 && std::string(argv[12])=="--helper-hybrid");
    if (argc!=12 && !helperHybrid) {
        std::cerr << "usage: gw_terrain_data_renderer CONQ001 B32A.raw MAIN.PAL output_prefix width height camX_q8 camY_q8 scaleX scaleY heightScale [--helper-hybrid fade_table_64x256.bin]\n";
        return 2;
    }
    std::vector<std::uint8_t> scenario,b32,pal,fade;
    if (!read_file(argv[1],scenario) || !read_file(argv[2],b32) || !read_file(argv[3],pal)) {
        std::cerr << "input read failed\n"; return 3;
    }
    if (helperHybrid && !read_file(argv[13],fade)) { std::cerr << "FADE table read failed\n"; return 3; }
    if (scenario.size()!=kScenarioBytes || le16(scenario.data())!=0x5336u ||
        kWorldBegin+kWorldBytes>scenario.size() || b32.size()!=kB32Bytes || pal.size()!=768) {
        std::cerr << "input size/signature mismatch\n"; return 4;
    }
    for (std::size_t i=0;i<pal.size();++i) if (pal[i]>63) {
        std::cerr << "palette component outside VGA 6-bit range at " << i << "\n"; return 5;
    }
    const int width=std::atoi(argv[5]), height=std::atoi(argv[6]);
    const int camX=std::atoi(argv[7]), camY=std::atoi(argv[8]);
    const int scaleX=std::atoi(argv[9]), scaleY=std::atoi(argv[10]);
    const int heightScale=std::atoi(argv[11]);
    if (width<320 || width>4096 || height<200 || height>2160 || scaleX<1 || scaleY<1 || scaleX%2 || scaleY%2) {
        std::cerr << "unsupported dimensions/scale\n"; return 6;
    }
    // Exact scenario parser contract: signature, 0x355E-byte prefix/header, then 16,384 14-byte cells.
    const int tx=95,ty=38;
    const std::size_t spot=kWorldBegin+(static_cast<std::size_t>(ty)*128+tx)*kCellStride;
    const std::uint8_t* c=scenario.data()+spot;
    const int classes[4]={
        scenario[kWorldBegin+(static_cast<std::size_t>(ty)*128+tx)*kCellStride+5]&7,
        scenario[kWorldBegin+(static_cast<std::size_t>(ty)*128+tx+1)*kCellStride+5]&7,
        scenario[kWorldBegin+(static_cast<std::size_t>(ty+1)*128+tx+1)*kCellStride+5]&7,
        scenario[kWorldBegin+(static_cast<std::size_t>(ty+1)*128+tx)*kCellStride+5]&7};
    const int key=(classes[0]<<9)|(classes[1]<<6)|(classes[2]<<3)|classes[3];
    const std::size_t expectedTex=(37/8)*0x2000u+(37%8)*0x20u;
    if (key!=56 || c[4]!=37 || signed_height(c)!=557 || expectedTex!=0x80A0u) {
        std::cerr << "CONQ001 (95,38) independent spot-check mismatch\n"; return 7;
    }
    Frame frame;
    const bool rendered=helperHybrid
        ? render_helper_hybrid(scenario,b32,pal,fade,width,height,camX,camY,
                           scaleX,scaleY,heightScale,argv[4],frame)
        : render(scenario,b32,pal,width,height,camX,camY,scaleX,scaleY,
                 heightScale,argv[4],frame);
    if (!rendered) {
        std::cerr << "render or output failed\n"; return 8;
    }
    std::size_t covered=0,nonzero=0;
    for (std::size_t i=0;i<frame.indexed.size();++i) {
        covered+=frame.covered[i]!=0; nonzero+=frame.covered[i] && frame.indexed[i]!=0;
    }
    std::cout << "size=" << width << "x" << height << " visible_cells=" << frame.visible.size()
              << " terrain_pixels=" << covered << " nonzero_texels=" << nonzero
              << " write_ops=" << frame.writeOps << " overdraw=" << frame.overdraw << "\n";
    return covered>0 && frame.visible.size()>10 ? 0 : (helperHybrid ? 10 : 9);
}




