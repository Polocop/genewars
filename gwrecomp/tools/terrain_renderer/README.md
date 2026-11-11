# Terrain renderer adapter boundary

`gw_terrain_renderer.h` is the boundary between the interactive host and the
opt-in terrain implementation. The host supplies a copied world view, the
decoded texture bank, output dimensions, viewport/camera parameters, and
receives indexed pixels plus coverage. `gw_demo_sdl2.exe` selects this backend
only with `GW_RENDER_BACKEND=terrain_modern`; the original lifted renderer
remains the default.

The implementation behind this boundary is experimental. Keep the API and the
host-side snapshot/render scheduling independent from assumptions about the
original texture strips, B32 layout in guest RAM, cell-code lookup, projection,
UV/rotation, or active RGB palette. Replace those implementation details only
after the GeneWars 1.1 runtime evidence establishes each one. In particular,
the Hermes P2 notes still mark strip-versus-tile interpretation and active
palette as unresolved; those notes are research inputs, not runtime contracts.

Camera interpolation is a separate pure runtime helper in
`runtime/gw_camera_interpolation.h`. It consumes two immutable camera samples
and a presentation timestamp; it has no access to guest RAM. The interactive
harness owns snapshot capture and SDL presentation because those operations
depend on the harness's guest-memory layout and host renderer.

The modern path reserves the measured 176-pixel HUD width. It keeps the
original 640x480 frame as the visual base and uses the experimental map only
to extend the view beyond the original right edge. Its map center stays at the
original viewport center (x=384, scaled with output height), so widening the
surface reveals additional map area instead of recentering the camera. The
extension still uses the measured 32-by-8 scale and 43-pixel vertical anchor
correction; those values improve its alignment but do not establish authentic
tile orientation, side faces, UV mapping, or entity sprite projection. Black
uncovered pixels remain possible in the experimental extension. The original
backend remains the default and 640x480 output follows the original renderer.
