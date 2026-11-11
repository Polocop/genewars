// ============================================================================
// gw_authentic_terrain_math.h
//
// Authentic (decompiled) terrain-math extraction of FUN_00065F20
// (0x65F20..0x665A0) from GeneWarsFX 1.1 (genewars-1_1.exe, LE base 0).
//
// Sources:
//   - E:/CODEX/gw_65f20_capstone.txt            (Capstone disassembly)
//   - evidence/fun_65f20_authentic_pipeline_reconstruction.json
//   - evidence/fun_65f20_e19c0_before_after_samples.json
//   - tests/test_65f20_x86_math_vectors.py  (verified vectors)
//
// WHAT THE ORIGINAL DOES (faithful reading of the x86):
//
//   FUN_00065F20(eax = camera pointer, ecx = ?, edx = loop count N,
//                ebx = start index) walks a ring of map cells and emits
//   polygon vertex records for the rasterizer at 0xE19C0.
//
//   * Camera state lives in the caller's object at [eax]:
//       +0x00  word  cam_x_q8   (live guest address 0x00346D80)
//       +0x02  word  cam_y_q8   (live guest address 0x00346D82)
//     The function copies these words into stack slots that are then used as
//     the "base coordinate" terms (see below). The evidence samples record the
//     live values, e.g. turn 435: [20967, 13288], turn 436: [21192, 13257].
//
//   * Per-cell data is read from a 14-byte record in the map table at
//         0x11AF86 + row_stride + col_stride
//     where (from the verified address expression in the reconstruction JSON)
//         row_stride = ((row_index & 0x7F) << 8)      // lea/shl pattern
//         col_stride = ((col_index & 0x7F) * 14)
//     i.e. an 8-byte stride per row-index step and a 14-byte stride per
//     column-index step, both masked to 7 bits (128-entry wrap).
//
//     Record layout (14 bytes), all offsets relative to the record base:
//         +0x00  int16    coord_word     (MOVSX WORD; horizontal input)
//         +0x02  int16    height_word    (MOVSX WORD; SAR 6; IMUL scale)
//         +0x04  uint8    top_flag_a     (copied to temp record +0x0A)
//         +0x05  uint8    top_flag_b     (copied to temp record +0x0B;
//                                         gates node-flag bits in branches)
//         +0x0C  uint8    scale_byte     (unsigned multiplier, fixed-point)
//         +0x0D  uint8    cell_kind      (compared to 1 / 0x61 at 0x662CC and
//                                         0x664DE; drives the mode-6 pass index)
//
//   * Projection math (exact integer / fixed-point, verified against the
//     captured vectors in test_65f20_x86_math_vectors.py):
//
//       screen_x_like = s32_shift_right_6(
//                         s32( (s16(coord_word) << 8) * u8(scale_byte) )
//                       ) + 0x8000        (mod 2^32)
//
//     This is the instruction block at 0x66040..0x66067 (and its three
//     sibling copies at 0x660BB..0x660D9, 0x6617C..0x6619A,
//     0x663A0..0x663BD). The SBB/SAR sequence implements a signed right
//     shift by 6 with round-toward-negative-infinity semantics, exactly as
//     modelled by x86_horizontal_fixed() in the test file. Verified vectors:
//         (coord=0x1000, scale=0x00) -> 0x00008000
//         (coord=0x1000, scale=0x0B) -> 0x00034000
//
//       height_term = s32( (s16(height_word) >> 6) * s32(proj_scale) )
//
//     where proj_scale is the global at 0x184AB4 (captured value 0 in the
//     sampled pan, so the term was 0 there). The result is subtracted from a
//     vertical coordinate:
//         screen_y = [esp+0x74] - height_term
//     Horizontal screen_x comes from the x_right/x_left bounds at stack
//     offsets +0x6C/+0x84, alternating by corner.
//
//   * The vertex record consumed by E19C0 is STRICTLY 20 bytes (stride 0x14;
//     live guest records at 0x003FEB1C, 0x003FEB30, 0x003FEB44 in the
//     before/after samples). Layout, five 32-bit fields — RECONCILED
//     BYTE-EXACT against the turn-435 capture (0x662BE / 0x664CD):
//         +0x00  DWORD  screen_x    = x_right [esp+0x6C] for the right-side
//                                     records (V0/V2), x_left [esp+0x84] for
//                                     the left-side ones (V1/V3); integer
//                                     pixel value (captured: 0x280 / 0x260)
//         +0x04  DWORD  screen_y    = [esp+0x74] - height_delta(height_word,
//                                     g_184ab4) — the camera y-accumulator
//                                     with the height term subtracted
//                                     (captured: -32, -16, 0, +16)
//         +0x08  DWORD  u_fp16      = captured B32 texture U, 0 or 0x1FFFFF
//         +0x0C  DWORD  v_fp16      = captured B32 texture V, 0 or 0x1FFFFF
//         +0x10  DWORD  shade_fp16  = gw_horizontal_fixed_point(coord_word,
//                                     scale_byte) — the ONLY field fed by
//                                     the x86 fixed-point expression
//                                     (captured: 0x00008000 / 0x00034000 /
//                                     0x00104000)
//
//     NOTE ON THE GWVertex20 FIELD MAPPING:
//     GWVertex20 reproduces exactly the 20-byte stride above:
//         screen_x   <- record +0x00   (x_right / x_left emission slots)
//         screen_y   <- record +0x04   ([esp+0x74] base - height delta)
//         u_fp16     <- record +0x08   (captured B32 U value)
//         v_fp16     <- record +0x0C   (captured B32 V value)
//         shade_fp16 <- record +0x10   (result of the x86 fixed-point math)
//     The two topology flag bytes (map record +0x04/+0x05) are NOT part of
//     the 20-byte vertex record; they stay in the 14-byte map record and
//     drive palette-table selection (see gw_topology_palette_indices).
//
//   * CORRECTION 2026-10-26 (turn-435 byte-exact reconciliation of the five
//     DWORDs at 0x662BE / 0x664CD): the live capture proves that +0x00 holds
//     the x_right/x_left emission slots (NOT a projected coordinate) and
//     +0x04 holds [esp+0x74] - height_delta (the y accumulator minus the
//     height term) — the earlier revision had swapped these two assignments.
//     With g_184ab4 = 0 at turn 435 the height term vanishes, so +0x04 equals
//     the raw [esp+0x74] values (-32, -16, 0, +16) exactly as captured.
//     The +0x08/+0x0C values vary by emission callsite; the captured triplets
//     are reproduced explicitly by gw_set_live_pair_uv.
//
//   * Captured U/V assignment is callsite-specific, not a fixed property of
//     each source corner. Only +0x10 (shade_fp16) receives the fixed-point
//     attribute result.
//     The two topology bytes (+0x04/+0x05 of the map record) are copied
//     separately and select palette entries via the tables at 0x114A08
//     (indexed by the low nibble of flag_a) and 0x105BF8 (indexed by
//     (flag_b & 0x70) >> 2). Those lookups happen inside the emission path
//     (0x661E1..0x66209 and 0x663FA..0x66422) and set the global at 0x100108
//     before each E19C0 call — the texture-palette selection for the cell.
//
//   * CORRECTION (base of projection, audit of 0x66162 / 0x66384):
//     ALL FOUR corner builds subtract their height term from [esp+0x74]
//     for screen_y:
//         0x66031  mov eax,[esp+0x74] ; sub eax,edx  (V0, block 0x66021)
//         0x660B1  mov edx,[esp+0x74] ; sub edx,eax  (V1, block 0x660A1)
//         0x66172  mov edx,[esp+0x74] ; sub edx,eax  (V2, block 0x66162)
//         0x66394  mov edx,[esp+0x74] ; sub edx,eax  (V3, block 0x66384)
//     The accumulator advances by [0x184AA8] between corner builds. Captured
//     turn-435 inputs are x_right=[esp+0x6C]=640, x_left=[esp+0x84]=608,
//     and y bases -32,-16,0,+16.
//     The second stack slot [esp+0x8C] is the MAP-CELL INDEX accumulator:
//     it is incremented (0x66143/0x6614A, 0x66354) and folded into the
//     0x11AF86 table address via (idx & 0x7F) * 14. It NEVER participates
//     in the screen-coordinate base. Earlier revisions wrongly used it as a
//     "base_y" for V2/V3; that model is removed.
//
//   * CORRECTION 2026-10-26 (map-table row stride, Bug 3): the x86 row
//     term is `imul idx, 0x700` at 0x660F7, 0x6611B, 0x66139 and 0x66372 —
//     NOT a `shl 8` (256). The live dump confirms it: 0x305DBC - 0x3056BC
//     = 0x700 = 1792 = 128 * 14 (128 records x 14-byte record). Hence
//     addr = 0x11AF86 + row*0x700 + col*14. The earlier `(row & 0x7F) << 8`
//     model (stride 256) is removed.
//
//   * CORRECTION 2026-10-26 (screen coordinate fields, Bug 3): the live
//     E19C0 vertex samples carry INTEGER PIXEL values at +0x00 (640, 608)
//     and +0x04 (-32, -16, 0). The 0x8000-biased fixed-point expression
//     (gw_horizontal_fixed_point, captured values 0x00008000 / 0x00034000)
//     is the SHADE/attribute channel only (+0x10); it is not a screen
//     coordinate. screen_y is the [esp+0x74] accumulator minus height.
//
//   * CORRECTION 2026-10-26 (observed call order): 0x662BE passes V0,V2,V1;
//     0x664CD passes V1,V2,V3. This is a byte-level callsite finding and is
//     not by itself a claim about complete screen-space mesh coverage.
//
//   * CORRECTION 2026-10-26 (captured UVs): Pair A uses
//     (MAX,MAX),(MIN,MIN),(MAX,MIN); Pair B uses
//     (MIN,MAX),(MAX,MAX),(MAX,MIN). These per-callsite values are set by
//     gw_set_live_pair_uv and verified against all 120 captured bytes.
//
//   * Triangle emission: six static callsites to 0xE19C0 exist
//     (0x662BE, 0x6630A, 0x6634F, 0x664CD, 0x6651C, 0x66564). They form
//     two pairs, one per logical triangle of the cell quad; each pair is
//     main pass + complementary mode-6 pass + a conditional 0x0F pass:
//
//         PAIR A (call order: V0,V2,V1):
//           0x662BE  mode 0 or 5  (see gw_select_main_pass_mode)
//           0x6630A  mode 6       — gated on V2.cell_kind (record +0x0D);
//                                    palette set from [idx*4+0x114C7C] where
//                                    idx = floor_div_32(cell_kind) clamped to
//                                    0..2 (0x662C3..0x662EB)
//           0x6634F  mode 0x0F    — gated on (cam_flags & 0x40)
//                                         && (V0.screen_x > 0)          (seta)
//                                         && !(V0.top_flag_b & 0x20)
//
//         PAIR B (triangle 2: V1, V2, V3):
//           0x664CD  mode 0 or 5  (0x66493..0x664BA, identical gate on
//                                    V1/V2/V3 screen_x)
//           0x6651C  mode 6       — same 0x114C7C lookup as pair A
//           0x66564  mode 0x0F    — same gate as 0x6634F (both reads of the
//                                    V0 temp record: 0x66316..0x6634F and
//                                    0x66521..0x66564)
//
//     Each call passes (eax = ptr to 20-byte record #1, edx = ptr to record
//     #2, ebx = ptr to record #3) — E19C0 sorts the three vertices by their
//     +0x04 field and rasterizes the triangle. The mode byte at 0x102E25 is
//     set before each call: 0 (plain), 5 (clip-active variant when a corner
//     coordinate is nonzero), 6 (complementary pass using table 0x114C7C),
//     0x0F (conditional pair). The x86 cull gates screen the THREE records
//     each pair feeds to E19C0 for screen_x < 0: pair A screens V0/V2/V1
//     in its live call order and pair B screens the
//     V1/V2/V3 records (0x663E4..0x663F2, [esi]/[ecx]/[ebp]). In array order
//     that is v[0], v[1], v[3] for pair A and v[1], v[2], v[3] for pair B.
//
//   * Loop structure: the outer loop iterates over `N` cells (edx at entry),
//     advancing two independent 7-bit-masked indices (the edi/ebx-style
//     counters at stack slots esp+0x7C and esp+0x8C); the inner body builds
//     up to four corner records per cell (V0/V1 via the 0x66021/0x660A1
//     paths, V2/V3 via the 0x66162/0x66384 paths), applies the culling test,
//     and performs the emission passes above.
//
// ============================================================================
#pragma once

#include <cstdint>
#include <cstddef>

namespace gw::terrain {

// ----------------------------------------------------------------------------
// Fixed-point helpers mirroring the exact x86 idioms in FUN_00065F20.
// ----------------------------------------------------------------------------

inline constexpr std::uint32_t GW_MAP_TABLE_BASE = 0x11AF86u;
inline constexpr std::uint32_t GW_MAP_RECORD_STRIDE_COL = 14u;   // imul idx, 0x0E
inline constexpr std::uint32_t GW_MAP_ROW_STRIDE = 0x700u;       // imul idx, 0x700
inline constexpr std::uint32_t GW_MAP_INDEX_MASK = 0x7Fu;       // and idx, 0x7F
inline constexpr std::int32_t  GW_FP_BIAS = 0x8000;             // add eax, 0x8000

// Guest sentinel compared against the current cell address in the mode 0/5
// gate (0x66284 / 0x66493: cmp ebx, 0x16CD60).
inline constexpr std::uint32_t GW_LAST_CELL_SENTINEL = 0x16CD60u;

// Sign-extend a 16-bit value (MOVSX EAX, WORD PTR [...]).
inline std::int16_t gw_movsx_word(std::uint16_t w) {
    return static_cast<std::int16_t>(w);
}

// Exact replica of the 0x66040..0x66067 block:
//   MOVSX EAX, WORD [EBX]; SHL EAX,8; MOV DL,BYTE[EBX+0xC]; IMUL EDX,EAX;
//   MOV EAX,EDX; SAR EDX,31; SHL EDX,6; SBB EAX,EDX; SAR EAX,6; ADD EAX,0x8000
// Verified against the captured vectors (see test_65f20_x86_math_vectors.py).
inline std::uint32_t gw_horizontal_fixed_point(std::uint16_t coord_word,
                                               std::uint8_t scale_byte) {
    const std::int32_t product = static_cast<std::int32_t>(
        static_cast<std::int64_t>(gw_movsx_word(coord_word)) << 8) *
        static_cast<std::int32_t>(scale_byte);
    // Signed right-shift by 6 implemented with the SBB idiom:
    //   sign = -1 if product < 0 else 0
    //   t = product - (sign << 6) - carry_from_shl(sign)
    //   r = t >> 6   (arithmetic)
    const std::int32_t sign = (product < 0) ? -1 : 0;
    const std::uint32_t shifted_sign = static_cast<std::uint32_t>(sign) << 6;
    const std::uint32_t carry = (sign == -1) ? 1u : 0u;
    const std::int32_t adjusted =
        static_cast<std::int32_t>(
            static_cast<std::uint32_t>(product) - shifted_sign - carry);
    const std::int32_t shifted = adjusted >> 6;
    return static_cast<std::uint32_t>(shifted + GW_FP_BIAS);
}

// Exact replica of the 0x66021..0x66035 height block:
//   MOVSX EAX, WORD [EBX+2]; SAR EAX,6; IMUL EDX,EAX   (EDX = [0x184AB4])
inline std::int32_t gw_height_delta(std::uint16_t height_word,
                                    std::int32_t projection_scale) {
    const std::int32_t h = static_cast<std::int32_t>(
        gw_movsx_word(height_word));
    return (h >> 6) * projection_scale;   // arithmetic shift, signed multiply
}

// ----------------------------------------------------------------------------
// Authentic 14-byte map cell record (read-only view).
// ----------------------------------------------------------------------------
struct GWMapCellRecord {
    std::uint16_t coord_word;   // +0x00  horizontal coordinate input (s16)
    std::uint16_t height_word;  // +0x02  height (s16, SAR 6 before use)
    std::uint8_t  top_flag_a;   // +0x04  topology flag (-> temp +0x0A)
    std::uint8_t  top_flag_b;   // +0x05  topology flag (-> temp +0x0B)
    std::uint8_t  pad_06[6];    // +0x06..+0x0B (unused by the math)
    std::uint8_t  scale_byte;   // +0x0C  unsigned fixed-point multiplier
    std::uint8_t  cell_kind;    // +0x0D  compared to 1 / 0x61 at 0x662CC /
                                //        0x664DE (mode-6 pass index input)
};
static_assert(sizeof(GWMapCellRecord) == 14, "map record must be 14 bytes");

// ----------------------------------------------------------------------------
// Vertex record passed to the rasterizer at 0xE19C0.
// STRICT 20-byte stride (0x14): the live E19C0 records observed on the stack
// sit at 0x003FEB1C, 0x003FEB30, 0x003FEB44 (20-byte spacing, five DWORDs).
// There is no extended/34-byte record; the topology flag bytes live in the
// 14-byte map record, not here.
// ----------------------------------------------------------------------------
#pragma pack(push, 1)
struct GWVertex20 {
    std::int32_t  screen_x;    // +0x00 x_right [esp+0x6C] / x_left [esp+0x84]
                               //       (integer pixel slot, captured 0x280/0x260)
    std::int32_t  screen_y;    // +0x04 [esp+0x74] - height_delta(height_word,
                               //       g_184ab4)  (captured -32/-16/0/+16)
    std::uint32_t u_fp16;      // +0x08 palette word 0 @ 0x105BF8+offset
                               //       (coincides with B32 U corner, 16.16)
    std::uint32_t v_fp16;      // +0x0C palette word 1 @ same table slot
                               //       (coincides with B32 V corner, 16.16)
    std::uint32_t shade_fp16;  // +0x10 resultado de gw_horizontal_fixed_point
};
#pragma pack(pop)
static_assert(sizeof(GWVertex20) == 20, "GWVertex20 must be exactly 20 bytes");
static_assert(offsetof(GWVertex20, u_fp16) == 8, "u_fp16 at +0x08");
static_assert(offsetof(GWVertex20, v_fp16) == 12, "v_fp16 at +0x0C");
static_assert(offsetof(GWVertex20, shade_fp16) == 16, "shade_fp16 at +0x10");

// ----------------------------------------------------------------------------
// B32 texture-block corner assignment (16.16 fixed point, 32x32 block).
// 0x001FFFFF == 31.9999 (the block's far edge); 0x00000000 == 0.0.
// ----------------------------------------------------------------------------
inline constexpr std::uint32_t GW_B32_UV_MAX = 0x001FFFFFu;   // 31.9999 @16.16
inline constexpr std::uint32_t GW_B32_UV_MIN = 0x00000000u;   // 0.0

enum class GWCorner : std::uint8_t {
    V0_NORTH = 0,   // U = min, V = min   (northwest world corner)
    V1_EAST  = 1,   // U = max, V = min   (northeast)
    V2_SOUTH = 2,   // U = max, V = max   (southeast)
    V3_WEST  = 3,   // U = min, V = max   (southwest)
};

// Authentic per-corner U/V of the B32 block, 16.16 fixed point.
// Perimeter-contiguous assignment (Bug 2 fix): walking the quad perimeter
// (Norte -> Este -> Sur -> Oeste) walks exactly one UV edge at a time, so
// no texture diagonal collapses onto a quad edge. With the perimeter
// partition (pair A = v0,v1,v3; pair B = v1,v2,v3) the two UV triangles
// are the exact halves of the B32 block:
//   (0,0)-(31,0)-(0,31) and (31,0)-(31,31)-(0,31)
// — no crossing, no colinearity.
inline void gw_b32_corner_uv(GWCorner corner,
                             std::uint32_t& out_u, std::uint32_t& out_v) {
    switch (corner) {
        case GWCorner::V0_NORTH: out_u = GW_B32_UV_MIN; out_v = GW_B32_UV_MIN; break;
        case GWCorner::V1_EAST:  out_u = GW_B32_UV_MAX; out_v = GW_B32_UV_MIN; break;
        case GWCorner::V2_SOUTH: out_u = GW_B32_UV_MAX; out_v = GW_B32_UV_MAX; break;
        case GWCorner::V3_WEST:  out_u = GW_B32_UV_MIN; out_v = GW_B32_UV_MAX; break;
    }
}

// ----------------------------------------------------------------------------
// Camera / projection context (values the function reads from globals and
// from the caller-provided camera object).
// ----------------------------------------------------------------------------
struct GWTerrainCameraState {
    // From the caller object at [eax] (live addresses 0x00346D80/0x00346D82):
    std::int32_t cam_x_base;   // seed for the esp+0x74 accumulator (q8 world x)
    std::int32_t cam_y_base;   // seed for the esp+0x8C slot (q8 world y; after
                               // the seed it is only the map-cell index base)

    // Globals read at 0x65F3B..0x65F8E (projection setup block):
    std::int32_t g_184aa4;     // [0x184AA4] multiplied by edx (loop count)
    std::int32_t g_184aa8;     // [0x184AA8] per-corner [esp+0x74] step g
                               // (0x6607A, 0x660EC, 0x66365)
    std::int32_t g_184aac;     // [0x184AAC] mixed into the esp+0x8C cell index
    std::int32_t g_184ab0;     // [0x184AB0] y-side offset (esp+0x8C seed term)
    std::int32_t g_184ab4;     // [0x184AB4] height projection scale

    // Flag byte at [camera_obj + 0x1C] (tests: bit 0x04, bit 0x40):
    std::uint8_t  camera_flags;

    // Mode selector written to 0x102E25 before each E19C0 call:
    //   0 = plain, 5 = clip variant, 6 = complementary pass, 0x0F = cond.
    std::uint8_t  emit_mode;

    // Exact screen-space bounds captured at 0x66021..0x664CD.  When this
    // flag is set, x is selected from the live left/right stack locals and
    // the per-corner accumulator argument is the y base ([esp+0x74]).
    // The default keeps older synthetic math fixtures source-compatible.
    std::int32_t  live_x_left;
    std::int32_t  live_x_right;
    bool          use_live_screen_axes;

    // Guest address of the current map-cell record (ebx) at the emission
    // sites; the mode 0/5 gate compares it with GW_LAST_CELL_SENTINEL.
    std::uint32_t current_cell_addr;
};

// ----------------------------------------------------------------------------
// gw_project_cell_vertices
//
// Reproduces the per-corner projection math of FUN_00065F20 for ONE map cell
// record: computes the two fixed-point coordinate terms exactly as the x86
// does (horizontal fixed-point with the 0x8000 bias, and the height delta
// subtracted from the camera-derived base), and fills a GWVertex20.
//
// Parameters:
//   rec        - the 14-byte map cell record (see GWMapCellRecord).
//   cam        - camera/projection state (bases + scales + flags).
//   base_x     - historical parameter name; in exact-axis mode this is the
//                [esp+0x74] per-corner screen-y accumulator. It advances by
//                g=[0x184AA8] for each preceding corner. [esp+0x8C] is the
//                map-cell index, not a screen coordinate.
//   corner     - which cell corner this vertex is (selects the authentic
//                B32 U/V corner pair; see gw_b32_corner_uv).
//
// Returns the projected vertex with (CORRECTED field assignment):
//   screen_x   = live_x_right for V0/V2, live_x_left for V1/V3 (captured
//                stack locals [esp+0x6C]/[esp+0x84]) when exact axes are set.
//   screen_y   = [esp+0x74] - height_delta(height_word, g_184ab4).
//                The argument named base_x by older callers is the actual
//                per-corner y accumulator in this exact mode.
//   u_fp16     = authentic B32 U corner for `corner` (16.16: 0x00000000 or
//                0x001FFFFF)
//   v_fp16     = authentic B32 V corner for `corner`
//   shade_fp16 = gw_horizontal_fixed_point(coord_word, scale_byte) — the
//                ONLY field fed by the x86 fixed-point expression
//                (captured values 0x00008000 / 0x00034000 land here)
// ----------------------------------------------------------------------------
inline GWVertex20 gw_project_cell_vertices(const GWMapCellRecord& rec,
                                           const GWTerrainCameraState& cam,
                                           std::int32_t base_x,
                                           GWCorner corner) {
    GWVertex20 v{};

    // --- screen coordinates -------------------------------------------------
    //   movsx eax, word [ebx+2] ; sar eax,6 ; imul edx,eax (edx=[0x184AB4])
    //   mov eax/edx, [esp+0x74] ; sub <base>, eax/edx
    const std::int32_t height_term =
        gw_height_delta(rec.height_word, cam.g_184ab4);
    if (cam.use_live_screen_axes) {
        const bool right_column =
            corner == GWCorner::V0_NORTH || corner == GWCorner::V2_SOUTH;
        v.screen_x = right_column ? cam.live_x_right : cam.live_x_left;
    } else {
        v.screen_x = base_x - height_term;
    }

    // --- screen_y: camera y-accumulator - height term (Bug 3 fix) -----------
    //   The live 0xE19C0 vertex samples carry INTEGER PIXEL values at +0x04
    //   (-32, -16, 0). The 0x8000-biased fixed-point expression is the
    //   SHADE/attribute channel only (+0x10); it must NOT be written into
    //   screen_y. screen_y comes from the camera y-accumulator with the
    //   height term subtracted, exactly as screen_x comes from the x
    //   accumulator.
    v.screen_y = (cam.use_live_screen_axes ? base_x : cam.cam_y_base) -
                 height_term;

    // --- u_fp16 / v_fp16: authentic B32 block corner (16.16) ----------------
    gw_b32_corner_uv(corner, v.u_fp16, v.v_fp16);

    // --- shade_fp16: the sole output of the x86 fixed-point expression ------
    v.shade_fp16 = gw_horizontal_fixed_point(rec.coord_word, rec.scale_byte);

    return v;
}

// Topology-driven palette indices exactly as computed at 0x661E1..0x66209:
//   pal_a = table_0x114A08[ (flag_a & 0x0F) ]        (low nibble)
//   pal_b = table_0x105BF8 + 8 * ( (flag_b & 0x70) >> 2 )
// The tables themselves live in guest memory; the caller supplies pointers.
inline void gw_topology_palette_indices(const GWMapCellRecord& rec,
                                        const std::uint32_t* table_114a08,
                                        std::uint32_t* out_pal_a,
                                        std::uint32_t* out_pal_b_offset) {
    if (out_pal_a != nullptr) {
        *out_pal_a = table_114a08[rec.top_flag_a & 0x0Fu];
    }
    if (out_pal_b_offset != nullptr) {
        *out_pal_b_offset =
            static_cast<std::uint32_t>((rec.top_flag_b & 0x70u) >> 2) * 8u;
    }
}

// ----------------------------------------------------------------------------
// Emission model: the six E19C0 callsites of FUN_00065F20, faithfully
// structured as two triangle pairs (main + mode-6 complement + conditional
// mode-0x0F pass each).
// ----------------------------------------------------------------------------

// Emission mode byte written to [0x102E25] immediately before the E19C0 call.
enum class GWEmitMode : std::uint8_t {
    kPlain = 0x00,        // all three pair vertices at screen_x == 0 AND
                           // current_cell_addr == GW_LAST_CELL_SENTINEL
    kClip = 0x05,         // any of the pair's screen_x nonzero (default path)
    kComplementary = 0x06,// post-main pass, palette from table 0x114C7C
    kConditional = 0x0F,  // gated extra pass (0x6634F / 0x66564)
};

// Texture-table identifier carried by each emission (what the original set
// into [0x100108] before the E19C0 call):
//   kTopology  - table 0x114A08 indexed by (V_first.top_flag_a & 0x0F),
//                paired with the 0x105BF8 offset (flag_b & 0x70) >> 2.
//                Set at 0x661E1/0x663FA before the main-pass call and reused
//                by the 0x0F pass (no re-lookup between main and 0x0F).
//   kC7c       - table 0x114C7C indexed by the mode-6 index computed from
//                V2.cell_kind (0x662EB/0x664FD: [idx*4 + 0x114C7C]).
//   k105bf8    - secondary palette table 0x105BF8 + 8 * ((flag_b & 0x70) >> 2)
//                (address formed at 0x66209/0x66422; the vertex +0x08/+0x0C
//                words are filled from the record pointed by it).
enum class GWTextureTable : std::uint8_t {
    kTopology = 0,
    kC7c = 1,
    k105bf8 = 2,
};

// One E19C0 emission: the three 20-byte vertex records the original feeds as
// (eax, edx, ebx), the mode byte it programmed into 0x102E25, and the
// texture table it set into 0x100108 before the call.
struct GWTriangleEmit {
    GWVertex20       v[3];          // the three 20-byte vertex records
    GWEmitMode       emit_mode;     // 0 / 5 / 6 / 0x0F (see GWEmitMode)
    GWTextureTable   texture_table; // palette source (see GWTextureTable)
    std::uint8_t     source_corner[3]; // V0..V3 identity; UVs are callsite-specific
};

// UVs are assigned by the original emission callsite, not by an immutable
// source-corner identity.  In particular V1/V2 have different B32 corners
// in the two calls (0x662BE vs 0x664CD); preserve the captured callsite data.
inline void gw_set_live_pair_uv(GWVertex20 (&vertices)[3], bool pair_a) {
    if (pair_a) {
        vertices[0].u_fp16 = GW_B32_UV_MAX; vertices[0].v_fp16 = GW_B32_UV_MAX;
        vertices[1].u_fp16 = GW_B32_UV_MIN; vertices[1].v_fp16 = GW_B32_UV_MIN;
        vertices[2].u_fp16 = GW_B32_UV_MAX; vertices[2].v_fp16 = GW_B32_UV_MIN;
    } else {
        vertices[0].u_fp16 = GW_B32_UV_MIN; vertices[0].v_fp16 = GW_B32_UV_MAX;
        vertices[1].u_fp16 = GW_B32_UV_MAX; vertices[1].v_fp16 = GW_B32_UV_MAX;
        vertices[2].u_fp16 = GW_B32_UV_MAX; vertices[2].v_fp16 = GW_B32_UV_MIN;
    }
}

// Mode 0/5 selection (0x66284..0x662AB and 0x66493..0x664BA, identical logic
// for both pairs): mode 5 is the loop-entry default; it is reset to 0 only
// when the current cell is the sentinel cell AND all three vertices of the
// pair have screen_x == 0. `sx` are the three screen_x values in E19C0
// argument order (region +0x04: V_a, V_b, V_c of the pair).
inline GWEmitMode gw_select_main_pass_mode(const GWTerrainCameraState& cam,
                                           std::int32_t sx_a,
                                           std::int32_t sx_b,
                                           std::int32_t sx_c) {
    if (cam.current_cell_addr == GW_LAST_CELL_SENTINEL &&
        sx_a == 0 && sx_b == 0 && sx_c == 0) {
        return GWEmitMode::kPlain;   // xor bh,bh ; mov [0x102E25], bh
    }
    return GWEmitMode::kClip;        // mov byte ptr [0x102e25], 5
}

// Mode-6 complementary-pass gate + 0x114C7C index (0x662C3..0x662EB and
// 0x664D2..0x664FD): kind = V2.cell_kind (record +0x0D of the pair's third
// vertex source cell). The pass runs only for kind in (1, 0x61); the table
// index is floor(kind / 32) of the clamped value, i.e. 0 for kind in
// [1,0x20], 1 for [0x20,0x40], 2 for kind >= 0x41 (clamped). The x86 uses
// dec/sbb/sar-5, which for the clamped range is exactly that floor division.
inline bool gw_complementary_pass_index(std::uint8_t kind,
                                        std::uint32_t* out_table_index) {
    if (kind <= 1u) {
        return false;                        // cmp edx,1 ; jle skip
    }
    if (kind >= 0x61u) {
        if (out_table_index != nullptr) *out_table_index = 2u;
        return true;                          // mov eax,2
    }
    if (out_table_index != nullptr) {
        *out_table_index = static_cast<std::uint32_t>(
            (static_cast<std::uint32_t>(kind) - 1u) / 32u);
    }
    return true;
}

// Conditional (mode 0x0F) pass gate, decoded from 0x66316..0x6634F and
// 0x66521..0x66564. BOTH conditional callsites read the FIRST cell's V0 temp
// record ([esp+0x70]):
//   ([camera_obj + 0x1C] & 0x40) != 0            (test byte, 0x40)
//   AND  V0.screen_x > 0                         (cmp 0 / seta — strictly >)
//   AND  !(V0.top_flag_b & 0x20)                 (test byte [rec+0xB], 0x20)
inline bool gw_conditional_emit_active(const GWMapCellRecord& v0_record,
                                       std::int32_t v0_screen_x,
                                       std::uint8_t camera_flags) {
    if ((camera_flags & 0x40u) == 0u) return false;
    if (v0_screen_x <= 0) return false;   // seta: carry set <=> v0 > 0
    if ((v0_record.top_flag_b & 0x20u) != 0u) return false;
    return true;
}

// ----------------------------------------------------------------------------
// gw_emit_cell_triangles
//
// Reproduces the full per-cell emission of FUN_00065F20: given the four
// corner records of one map cell (as the original reads them from the map
// table via the 0x11AF86 + row<<8 + col*14 addressing), the camera state,
// and the current [esp+0x74] x-base, it projects every corner and emits the
// structured GWTriangleEmit entries in the exact callsite order:
//
//   out[0]  @0x662BE  PAIR A main        mode 0/5,  table kTopology
//   out[1]  @0x6630A  PAIR A mode 6      gated,     table kC7c
//   out[2]  @0x6634F  PAIR A mode 0x0F   gated,     table kTopology (reused)
//   out[3]  @0x664CD  PAIR B main        mode 0/5,  table kTopology
//   out[4]  @0x6651C  PAIR B mode 6      gated,     table kC7c
//   out[5]  @0x66564  PAIR B mode 0x0F   gated,     table kTopology (reused)
//
// Only entries that the original would actually execute are written (gates
// evaluated against the authentic x86 conditions); `count_out` receives the
// number of written entries (0, 2, 3, 4, 5 or 6).
//
// Projection bases (live capture): [esp+0x74] advances by g after each
// corner and supplies screen_y in exact-axis mode; screen_x comes from the
// x_left/x_right bounds. [esp+0x8C] is the map-cell index folded into the
// 0x11AF86 addressing.
//
// Corner naming (matching the stack-record roles in the disassembly):
//   corner0 = record projected at 0x66021..0x66073 (temp record, esp+0x94)
//             -> V0 (base b0)
//   corner1 = record projected at 0x660A1..0x660E5 (esi slot)
//             -> V1 (base b0 + g)
//   corner2 = record projected at 0x6615F..0x661A6 (ecx slot)
//             -> V2 (base b0 + 2g)
//   corner3 = record projected at 0x66381..0x663C9 (ebp slot)
//             -> V3 (base b0 + 3g)
//
// Cull gates (CORRECTED, faithful to the x86 register roles): pair A
// screens the three records it feeds E19C0 — V0 ([esp+0x94]), V1 ([esi])
// and V3 ([ecx], 0x661C5..0x661D2) — and is skipped when all three have
// screen_x < 0; pair B screens its own records V1/V2/V3 (0x663E4..0x663F2).
//
// Parameters:
//   corners   - the four corner records, in the order V0..V3 above.
//   cam       - camera / projection state.
//   base_x    - current value of the [esp+0x74] per-corner accumulator.
//   out       - output array holding up to six GWTriangleEmit entries.
//   count_out - receives how many emissions were written (may be nullptr).
//
// Returns true if at least one pair passed its cull gate (i.e. at least one
// emission was written).
// ----------------------------------------------------------------------------
inline bool gw_emit_cell_triangles(const GWMapCellRecord (&corners)[4],
                                   const GWTerrainCameraState& cam,
                                   std::int32_t base_x,
                                   GWTriangleEmit (&out)[6],
                                   int* count_out = nullptr) {
    // Project all four corners against the single [esp+0x74] accumulator,
    // advancing by g = [0x184AA8] after each build (0x66076..0x66081,
    // 0x660E8..0x660FD, 0x66361..0x6637D). No second "base_y" exists:
    // [esp+0x8C] is only the map-cell index (see file-header correction).
    static constexpr GWCorner kCornerOf[4] = {
        GWCorner::V0_NORTH, GWCorner::V1_EAST,
        GWCorner::V2_SOUTH, GWCorner::V3_WEST,
    };
    GWVertex20 v[4];
    std::int32_t bx = base_x;
    for (int i = 0; i < 4; ++i) {
        v[i] = gw_project_cell_vertices(corners[i], cam, bx, kCornerOf[i]);
        bx += cam.g_184aa8;
    }

    int count = 0;

    // ------------------------------------------------------------------
    // PAIR A — live E19C0 call order is V0, V2, V1 at 0x662BE.
    // ------------------------------------------------------------------
    const bool pairA_culled =
        v[0].screen_x < 0 && v[2].screen_x < 0 && v[1].screen_x < 0;
    if (!pairA_culled) {
        // 0x662BE: main pass, mode 0 or 5 (0x66284..0x662AB gate), palette
        // from table 0x114A08 (0x661E1..0x66209) + 0x105BF8 offset.
        GWTriangleEmit& mainA = out[count++];
        mainA.v[0] = v[0];
        mainA.v[1] = v[2];
        mainA.v[2] = v[1];
        mainA.source_corner[0] = 0; mainA.source_corner[1] = 2; mainA.source_corner[2] = 1;
        gw_set_live_pair_uv(mainA.v, true);
        mainA.emit_mode = gw_select_main_pass_mode(
            cam, v[0].screen_x, v[2].screen_x, v[1].screen_x);
        mainA.texture_table = GWTextureTable::kTopology;

        // 0x6630A: mode-6 complementary pass, gated on the V2-slot record's
        // cell_kind (corners[2], 0x662C3..0x662EB); palette from table
        // 0x114C7C.
        std::uint32_t c7c_index = 0u;
        if (gw_complementary_pass_index(corners[2].cell_kind, &c7c_index)) {
            (void)c7c_index;  // table content resolved by the integrator
            GWTriangleEmit& compA = out[count++];
            compA.v[0] = v[0];
            compA.v[1] = v[2];
            compA.v[2] = v[1];
            compA.source_corner[0] = 0; compA.source_corner[1] = 2; compA.source_corner[2] = 1;
            gw_set_live_pair_uv(compA.v, true);
            compA.emit_mode = GWEmitMode::kComplementary;
            compA.texture_table = GWTextureTable::kC7c;
        }

        // 0x6634F: conditional mode-0x0F pass (0x66316..0x6634F gate on the
        // V0 temp record); palette reuses the topology value left in
        // [0x100108] by the last main/mode-6 lookup.
        if (gw_conditional_emit_active(corners[0], v[0].screen_x,
                                       cam.camera_flags)) {
            GWTriangleEmit& condA = out[count++];
            condA.v[0] = v[0];
            condA.v[1] = v[2];
            condA.v[2] = v[1];
            condA.source_corner[0] = 0; condA.source_corner[1] = 2; condA.source_corner[2] = 1;
            gw_set_live_pair_uv(condA.v, true);
            condA.emit_mode = GWEmitMode::kConditional;
            condA.texture_table = GWTextureTable::kTopology;
        }
    }

    // ------------------------------------------------------------------
    // PAIR B — triangle (V1, V2, V3); records assembled at
    // 0x66424..0x6648F (V1 in the esi slot, V2 in ecx, V3 in the ebp slot).
    // ------------------------------------------------------------------
    const bool pairB_culled =
        v[1].screen_x < 0 && v[2].screen_x < 0 && v[3].screen_x < 0;
    if (!pairB_culled) {
        // 0x664CD: main pass, mode 0 or 5 (0x66493..0x664BA gate), topology
        // palette from the esi (V1) temp record (0x663FA..0x66422).
        GWTriangleEmit& mainB = out[count++];
        mainB.v[0] = v[1];
        mainB.v[1] = v[2];
        mainB.v[2] = v[3];
        mainB.source_corner[0] = 1; mainB.source_corner[1] = 2; mainB.source_corner[2] = 3;
        gw_set_live_pair_uv(mainB.v, false);
        mainB.emit_mode = gw_select_main_pass_mode(
            cam, v[1].screen_x, v[2].screen_x, v[3].screen_x);
        mainB.texture_table = GWTextureTable::kTopology;

        // 0x6651C: mode-6 complementary pass (0x664D2..0x664FD), same 0x114C7C
        // table/index logic as pair A (index reads the same V2 cell_kind).
        std::uint32_t c7c_index_b = 0u;
        if (gw_complementary_pass_index(corners[2].cell_kind, &c7c_index_b)) {
            (void)c7c_index_b;
            GWTriangleEmit& compB = out[count++];
            compB.v[0] = v[1];
            compB.v[1] = v[2];
            compB.v[2] = v[3];
            compB.source_corner[0] = 1; compB.source_corner[1] = 2; compB.source_corner[2] = 3;
            gw_set_live_pair_uv(compB.v, false);
            compB.emit_mode = GWEmitMode::kComplementary;
            compB.texture_table = GWTextureTable::kC7c;
        }

        // 0x66564: conditional mode-0x0F pass (0x66521..0x66564); the gate
        // reads the same V0 temp record as 0x6634F.
        if (gw_conditional_emit_active(corners[0], v[0].screen_x,
                                       cam.camera_flags)) {
            GWTriangleEmit& condB = out[count++];
            condB.v[0] = v[1];
            condB.v[1] = v[2];
            condB.v[2] = v[3];
            condB.source_corner[0] = 1; condB.source_corner[1] = 2; condB.source_corner[2] = 3;
            gw_set_live_pair_uv(condB.v, false);
            condB.emit_mode = GWEmitMode::kConditional;
            condB.texture_table = GWTextureTable::kTopology;
        }
    }

    if (count_out != nullptr) *count_out = count;
    return count > 0;
}

// Map-table addressing exactly as in the x86 (0x660F7/0x6611B/0x66139/
// 0x66372: `imul idx, 0x700` for the row term — NOT a `shl 8`):
//   addr = 0x11AF86 + ((row & 0x7F) * 0x700) + ((col & 0x7F) * 14)
// The row stride is 0x700 = 1792 = 128 records x 14 bytes. Live-dump
// cross-check: 0x305DBC - 0x3056BC = 0x700. The `col` term is driven by
// the [esp+0x8C] map-cell index accumulator — the SAME slot that the
// corner loops advance at 0x6614A/0x66354 (NOT a screen-coordinate base;
// see the file-header correction note).
inline std::uint32_t gw_map_record_address(std::uint32_t row_index,
                                           std::uint32_t col_index) {
    return GW_MAP_TABLE_BASE +
           ((row_index & GW_MAP_INDEX_MASK) * GW_MAP_ROW_STRIDE) +
           ((col_index & GW_MAP_INDEX_MASK) * GW_MAP_RECORD_STRIDE_COL);
}

// ----------------------------------------------------------------------------
// Ring-loop state: exact prologue (0x65F20..0x66020) and outer-loop step
// (0x66569..0x665A0) of FUN_00065F20.
//
// The function walks a RING of N map cells. The x86 keeps four stack slots
// that together form the loop state; this struct mirrors them one-to-one so
// the integrator can drive the same sequence without re-deriving it:
//
//   [esp+0x74]  base_x      — per-corner screen-coordinate accumulator.
//                             Seeded ONCE before the loop from the globals
//                             (see below), then advanced by g=[0x184AA8]
//                             after each of the THREE corner builds inside
//                             the cell body (0x66076..0x66081,
//                             0x660E8..0x660FD, 0x66361..0x6637D). It is
//                             NEVER reset per cell and never touched by the
//                             tail.
//   [esp+0x7C]  row_index   — the ROW threshold. Written ONLY by the
//                             prologue (seeded from ECX at 0x65F30, offset
//                             by -EBX at 0x65FD9/0x65FE3) and CONSTANT for
//                             the whole loop; the tail reloads it at
//                             0x66569 as the comparison threshold.
//   [esp+0x8C]  col_index   — the COLUMN / map-cell index. Seeded from the
//                             [0x184AAC]+[edx>>1] term stored at [esp+0x80]
//                             (0x65FAE/0x65FD2) and incremented by +1 each
//                             cell pass at 0x6614A/0x66158. Folded into the
//                             0x11AF86 table address via (idx&0x7F)*14.
//   [esp+0x88]  camera_ptr  — EAX at entry, the caller's camera object
//                             (0x65F29: mov [esp+0x88], eax).
//
// PROLOGUE (0x65F20..0x66020), instruction by instruction:
//
//   0x65F20..0x65F23  push esi/edi/ebp ; sub esp,0x98        (frame)
//   0x65F29           mov [esp+0x88], eax                    (camera_ptr = EAX)
//   0x65F30           mov [esp+0x7c], ecx                    (row seed = ECX)
//   0x65F34           mov byte [0x102e25], 5                 (emit mode default)
//   0x65F3B           mov eax, [0x184aa4]
//   0x65F40           imul eax, edx                          ([0x184AA4]*N)
//   0x65F43/0x65F45   xor cl,cl ; mov byte [0x102e24], cl
//   0x65F4B           mov ecx, [0x184aa4]
//   0x65F51           mov [esp+0x84], eax                    (N*G_A term)
//   0x65F58           add eax, ecx                           (N*G_A + G_A)
//   0x65F5A           mov [esp+0x6c], eax                    (emission arg slot)
//   0x65F5E/0x65F62   lea eax,[esp+0xc]; mov [esp+0x94],eax  (temp record ptr)
//   0x65F69           mov eax, edx                           (eax = N)
//   0x65F6B           mov edi, [0x184aac]
//   0x65F71           sar eax, 1                             (N >> 1)
//   0x65F73           add edi, eax                           ([0x184AAC]+(N>>1))
//   0x65F75           mov esi, esp                           (esi = V1 rec base)
//   0x65F77           mov [esp+0x80], edi                    (col seed source)
//   0x65F7E           mov edi, [0x184ab0]
//   0x65F84           lea ebp, [esp+0x18]                    (ebp = V3 rec base)
//   0x65F88           sub edi, eax                           ([0x184AB0]-(N>>1))
//   0x65F8A           lea ecx, [esp+0x24]                    (ecx = V2 rec base)
//   0x65F8E           mov eax, edi                           (eax = that value)
//   0x65F90           test dl, 1                             (parity of N)
//   0x65F93           jne 0x65fba                            (odd-N branch)
//     EVEN N (0x65F95..0x65FB8):
//       0x65F95         mov edx, [0x184aa8]                  (g)
//       0x65F9B         mov edi, edx
//       0x65F9D         mov [esp+0x74], edx                  (base_x = g)
//       0x65FA1         neg edi                              (-g)
//       0x65FA3         mov edx, [esp+0x80]                  (col seed src)
//       0x65FAA         mov [esp+0x74], edi                  (base_x = -g)
//       0x65FAE         mov [esp+0x8c], edx                  (col = seed)
//       0x65FB5         lea edi, [eax-1]                     (loop counter)
//       0x65FB8         jmp 0x65fd9
//     ODD N (0x65FBA..0x65FD2):
//       0x65FBA         mov edx, [0x184aa8]                  (g)
//       0x65FC0         neg edx                              (-g)
//       0x65FC2         add edx, edx                         (-2g)
//       0x65FC4         mov [esp+0x74], edx                  (base_x = -2g)
//       0x65FC8         mov edx, [esp+0x80]                  (col seed src)
//       0x65FCF         sub edi, 2
//       0x65FD2         mov [esp+0x8c], edx                  (col = seed)
//   0x65FD9           mov edx, [esp+0x7c]                    (row)
//   0x65FDD           sub edx, ebx                           (row -= start_idx)
//   0x65FDF           mov eax, [esp+0x74]                    (base_x)
//   0x65FE3           mov [esp+0x7c], edx                    (row committed)
//   0x65FE7           mov edx, edi                           (counter)
//   0x65FE9           sub eax, ebx                           (base_x -= start)
//   0x65FEB           and edx, 0x7f
//   0x65FEE           mov [esp+0x74], eax                    (base_x committed)
//   0x65FF2..0x6601A  compute first cell address =
//                     0x11AF86 + (row&0x7F)*0x700 + (col&0x7F)*14
//                     (lea [edx*8]; sub; shl 8 == *0x700; lea [ebx*8]; sub;
//                      add == *14); 0x6601D also commits the 14*col term to
//                      [esp+0x78] for the corner builds;
//   0x6601D           lea ebx, [edx+eax] -> mov [esp+0x78], eax
//   0x66021           ... first V0 corner build begins
//
// LOOP TAIL (0x66569..0x665A0), exact sequence:
//
//   0x66569           mov ebx, [esp+0x7c]                    (load row)
//   0x6656D           mov eax, esi
//   0x6656F           mov esi, ebp                           (V1 <- old V3)
//   0x66571           mov ebp, eax                           (V3 <- old V1)
//   0x66573           mov eax, [esp+0x94]
//   0x6657A           mov [esp+0x94], ecx                    (V0 <- old V2)
//   0x66581           mov ecx, eax                           (V2 <- old V0)
//   0x66583           cmp ebx, [esi]                         (row vs value at
//                                                             the OLD V3 rec)
//   0x66585           jg  0x660e8                            (continue if >)
//   0x6658B           mov eax, [esp+0x94]                    (= old V0 ptr)
//   0x66592           cmp ebx, [eax]                         (row vs value at
//                                                             the OLD V0 rec)
//   0x66594           jg  0x660e8                            (continue if >)
//   0x6659A           add esp, 0x98                          (fall through: exit)
//
// The tail FIRST rotates the four corner-slot assignments by two positions
// (V0<-oldV2, V1<-oldV3, V2<-oldV0, V3<-oldV1; period 2), THEN compares the
// row against the WORDS STORED IN the old V3 temp record and in the temp
// record whose pointer now sits in [esp+0x94] (old V0). The loop CONTINUES
// when row is greater than EITHER of those two values; it exits only when
// row <= value(oldV3) AND row <= value(oldV0). [esp+0x7C] itself is NEVER
// rewritten in the loop, so the compared threshold is constant; what changes
// per pass are the compared-against WORDS, which the corner builds write into
// the rotating temp records.
// ----------------------------------------------------------------------------
struct GWRingLoopState {
    // Stack-slot mirror (see comments above for the exact x86 provenance).
    std::int32_t  base_x;       // [esp+0x74] x-accumulator (seeded once, then
                                // advanced by g after each of the 3 corner
                                // builds in the body)
    std::int32_t  row_index;    // [esp+0x7C] row threshold (seed ECX, offset
                                // -start); CONSTANT for the whole loop
    std::int32_t  col_index;    // [esp+0x8C] column / map-cell index; advanced
                                // by +1 each cell pass (0x6614A/0x66158)
    std::int32_t  camera_ptr;   // [esp+0x88] EAX at entry (caller camera obj)

    // Loop-tail comparison bounds (the two WORDS the tail compares the row
    // against after rotating the corner slots: the value stored in the OLD V3
    // temp record, and the value stored in the temp record whose pointer now
    // sits in [esp+0x94] after the rotation, i.e. the OLD V0 record).
    std::int32_t  bound_a;      // value at old V3 rec (0x66583 cmp target)
    std::int32_t  bound_b;      // value at old V0 rec (0x66592 cmp target)

    // The four corner temp-record slots (V0..V3). In the original these hold
    // POINTERS into the 0x98-byte frame (stack offsets); we mirror them as
    // those offsets so the rotation is exact:
    //   V0 = [esp+0x94]  <- lea eax,[esp+0x0C]   -> offset 0x0C
    //   V1 = esi         <- mov esi,esp          -> offset 0x00
    //   V2 = ecx         <- lea ecx,[esp+0x24]   -> offset 0x24
    //   V3 = ebp         <- lea ebp,[esp+0x18]   -> offset 0x18
    // The loop tail (0x6656D..0x66581) rotates them by two positions each
    // pass (V0<-oldV2, V1<-oldV3, V2<-oldV0, V3<-oldV1; period 2), which
    // gw_step_ring_loop_state applies to this array.
    std::int32_t  corner_base[4];   // [0]=V0, [1]=V1, [2]=V2, [3]=V3

    // Globals captured during the prologue (values, not addresses):
    std::int32_t  g_184aa4;     // [0x184AA4] (multiplied by N at 0x65F40)
    std::int32_t  g_184aa8;     // [0x184AA8] = g, the per-corner-build step
    std::int32_t  g_184aac;     // [0x184AAC] (mixed into the col seed)
    std::int32_t  g_184ab0;     // [0x184AB0] (y-side term, 0x65F7E/0x65F88)
};

// Exact replica of the prologue seeding (0x65F20..0x66020). Reproduces how
// [esp+0x74]/[esp+0x7C]/[esp+0x8C]/[esp+0x88] are initialised from the entry
// arguments (eax = camera_ptr, ecx = row seed, edx = loop count N,
// ebx = start_index) and the globals 0x184AA4..0x184AB4.
//
// Parameters:
//   camera_ptr  — EAX at entry (caller camera object; stored to [esp+0x88]).
//   row_seed    — ECX at entry (stored to [esp+0x7C] at 0x65F30).
//   loop_count  — EDX at entry (N; drives the parity branch and the col seed
//                via [0x184AAC]+(N>>1)).
//   start_index — EBX at entry (subtracted from both row and base_x at
//                0x65FDD/0x65FE9).
//   g_184aa4/g_184aa8/g_184aac/g_184ab0 — the global values read in the
//                prologue (0x65F3B..0x65F95).
//
// Returns the fully-seeded state. `corner_base[]` is seeded with the
// prologue's frame offsets (V0=0x0C, V1=0x00, V2=0x24, V3=0x18);
// `bound_a`/`bound_b` start at 0 because the tail compares against the
// CONTENTS of the temp records, which only exist once the body's corner
// builds have written them — the integrator sets them from those record
// values before each gw_step_ring_loop_state call.
inline GWRingLoopState gw_init_ring_loop_state(std::int32_t camera_ptr,
                                               std::int32_t row_seed,
                                               std::int32_t loop_count,
                                               std::int32_t start_index,
                                               std::int32_t g_184aa4,
                                               std::int32_t g_184aa8,
                                               std::int32_t g_184aac,
                                               std::int32_t g_184ab0) {
    GWRingLoopState s{};
    s.camera_ptr = camera_ptr;                       // 0x65F29
    s.g_184aa4 = g_184aa4;
    s.g_184aa8 = g_184aa8;
    s.g_184aac = g_184aac;
    s.g_184ab0 = g_184ab0;

    const bool n_odd = (static_cast<std::uint32_t>(loop_count) & 1u) != 0u;
    const std::int32_t half_n = loop_count >> 1;     // 0x65F71 sar eax,1
    const std::int32_t g = g_184aa8;                 // [0x184AA8]

    // Col seed source: [0x184AAC] + (N >> 1)  (0x65F6B/0x65F73 -> [esp+0x80])
    const std::int32_t col_seed_src = g_184aac + half_n;

    // Parity branch selects the ONE-TIME base_x seed (0x65F90 test dl,1):
    //   even N: base_x = -g          (0x65FA1 neg edi ; 0x65FAA store)
    //   odd  N: base_x = -2*g        (0x65FC0 neg ; 0x65FC2 add edx,edx)
    s.base_x = n_odd ? (-2 * g) : (-g);

    // Both branches commit the SAME col seed (0x65FAE / 0x65FD2):
    s.col_index = col_seed_src;

    // Row: seeded from ECX (0x65F30), then offset by -start_index
    // (0x65FD9/0x65FDD/0x65FE3). Base_x is likewise offset by -start_index
    // (0x65FDF/0x65FE9/0x65FEE).
    s.row_index = row_seed - start_index;
    s.base_x   -= start_index;

    // Temp-record base terms computed in the prologue become the initial
    // loop-tail bounds: [esp+0x94] holds the V0 temp-record pointer and
    // [esp+0x80] holds the col-seed source; the tail compares row against
    // [esi] (V1 base) and [esp+0x94]. We expose both raw terms here.
    s.bound_a = col_seed_src;                        // [esp+0x80] term
    s.bound_b = g_184ab0 - half_n;                   // 0x65F7E/0x65F88 term
    return s;
}

// Exact replica of the outer-loop step (0x66569..0x665A0). Advances the row
// index by +1 (the tail reloads [esp+0x7C] as the next comparison operand,
// which the body has already incremented) and evaluates the two continue
// comparisons. Returns true if the loop CONTINUES (row > bound_a OR
// row > bound_b, matching the 0x66585/0x66594 `jg` targets); false means the
// ring is complete and the function would execute `add esp,0x98` and return.
//
// Note on base_x: the tail does NOT touch [esp+0x74]; it is advanced only by
// the per-corner-build adds inside the cell body (0x6607A/0x660EC/0x66365).
// This helper therefore leaves base_x untouched — the integrator applies the
// body's g-steps itself between calls.
inline bool gw_step_ring_loop_state(GWRingLoopState& s) {
    // 0x66569: mov ebx, [esp+0x7c]  — the row value to compare is the
    // CURRENT [esp+0x7C]; the body's last increment has already been applied,
    // so the next pass uses row_index + 1. Model the tail's effective next-row.
    const std::int32_t next_row = s.row_index + 1;

    // 0x66583/0x66585: cmp ebx,[esi] ; jg 0x660e8  (continue if next_row > a)
    // 0x66592/0x66594: cmp ebx,[eax] ; jg 0x660e8  (continue if next_row > b)
    const bool cont_a = next_row > s.bound_a;
    const bool cont_b = next_row > s.bound_b;

    // Commit the advanced row for the next iteration.
    s.row_index = next_row;

    return cont_a || cont_b;
}

// ----------------------------------------------------------------------------
// FADE.DAT shade lookup (0xE4198..0xE41A9) and light-row extraction.
//
// The rasterizer's inner shading step performs, verbatim:
//
//   0xE4198  mov al, byte ptr [ebx + esi]      ; AL = source texel (0..255)
//   0xE419F  mov al, byte ptr [eax + 0x362a54] ; AL = FADE table byte at
//                                                  DS_BASE+0x362A54+EAX
//   0xE41A9  mov byte ptr [edi], al            ; store shaded palette index
//
// EAX is a BYTE OFFSET into the 64x256 FADE table (guest 0x00362A54,
// 16 KiB dump sha256 b1297e2c...). Its layout is HIGH BYTE = light row
// (0..63), LOW BYTE = source texel (0..255). The live samples confirm this
// exactly: EAX=0x093D -> row 9 / texel 0x3D, EAX=0x083F -> row 8 / texel 63,
// EAX=0x1545 -> row 21 / texel 69, etc. The observed light levels in the
// turn-437 probe are {8,9,10,11,12,13,14,15,16,21}.
//
// HOW THE LIGHT COMPONENT IS PREPARED:
//   At E19C0, EBX loads shade_fp16, `shr ebx,8` executes, CX receives BX,
//   and the pixel loop later does `mov ah,ch`. Thus the initial vertex
//   component is shade_fp16[23:16] (0x8000 -> 0, 0x34000 -> 3,
//   0x104000 -> 16). E19C0 then interpolates this component; the byte in AH
//   at the FADE lookup is that live per-pixel interpolant, not a direct
//   `(shade >> 12) & 0x3f` extraction. The latter would wrap large values
//   and is not supported by the captured instruction sequence.
// ----------------------------------------------------------------------------
inline constexpr std::uint32_t GW_FADE_TABLE_GUEST_BASE = 0x00362A54u;
inline constexpr std::size_t   GW_FADE_TABLE_ROWS = 64u;   // light rows 0..63
inline constexpr std::size_t   GW_FADE_TABLE_COLS = 256u;  // texels 0..255
inline constexpr std::size_t   GW_FADE_TABLE_SIZE = GW_FADE_TABLE_ROWS * GW_FADE_TABLE_COLS;

// E19C0 shifts the vertex shade right by eight and later executes
// `mov ah,ch`; that selects original shade bits 16..23 as the initial
// per-vertex light component. Raster interpolation updates it per pixel.
// Return the captured starting component without modulo-64 wrapping.
inline std::uint8_t gw_shade_light_row(std::uint32_t shade_fp16) {
    return static_cast<std::uint8_t>((shade_fp16 >> 16) & 0xFFu);
}

// E19C0's E4198 address is ESI + EBX where EBX is assembled from the
// integer bytes of V and U: (V >> 16) in BH and (U >> 16) in BL.
// B32 rows therefore have the original 256-byte stride, even though only
// the first 32 texels of each row belong to this tile.
inline std::size_t gw_b32_source_offset(std::uint32_t u_fp16,
                                        std::uint32_t v_fp16) {
    const std::size_t u = static_cast<std::size_t>((u_fp16 >> 16) & 0xFFu);
    const std::size_t v = static_cast<std::size_t>((v_fp16 >> 16) & 0xFFu);
    return (v << 8) | u;
}

// Exact replica of the 0xE4198..0xE41A9 shading step. Given a source texel
// (0..255) and a light row (0..63), returns the shaded palette index read
// from the 64x256 FADE table: fade_table[row * 256 + texel].
//
// Parameters:
//   texel          — the source texture byte (AL after 0xE4198).
//   light_row      — the FADE row (AH / high byte of the EAX offset), 0..63.
//   fade_table_64x256 — pointer to the 16 KiB FADE table (64 rows x 256 cols,
//                       row-major, 1 byte/entry). Must be non-null and hold
//                       at least GW_FADE_TABLE_SIZE bytes.
inline std::uint8_t gw_apply_fade_shade(std::uint8_t texel,
                                        std::uint8_t light_row,
                                        const std::uint8_t* fade_table_64x256) {
    // The original indexes the active table directly; it does not wrap an
    // out-of-range shade through modulo 64. The caller supplies a valid row.
    const std::size_t row = static_cast<std::size_t>(light_row);
    const std::size_t col = static_cast<std::size_t>(texel);
    return fade_table_64x256[row * GW_FADE_TABLE_COLS + col];
}

// Convenience: given a vertex's shade_fp16 and a source texel, perform the
// full 0xE4198..0xE41A9 chain (derive the row, then index the FADE table).
inline std::uint8_t gw_apply_fade_shade_from_vertex(std::uint32_t shade_fp16,
                                                    std::uint8_t texel,
                                                    const std::uint8_t* fade_table_64x256) {
    return gw_apply_fade_shade(texel, gw_shade_light_row(shade_fp16),
                               fade_table_64x256);
}

}  // namespace gw::terrain
