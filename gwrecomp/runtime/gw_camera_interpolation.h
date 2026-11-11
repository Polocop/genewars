#ifndef GW_CAMERA_INTERPOLATION_H
#define GW_CAMERA_INTERPOLATION_H

#include <stdint.h>

typedef struct gw_camera_interpolation_input {
    uint32_t previous_turn;
    int previous_x_q8;
    int previous_y_q8;
    uint64_t previous_captured_at;
    int previous_valid;
    uint32_t current_turn;
    int current_x_q8;
    int current_y_q8;
    uint64_t current_captured_at;
    int current_valid;
    uint64_t now;
    uint64_t counter_frequency;
} gw_camera_interpolation_input;

typedef struct gw_camera_interpolation_result {
    double camera_x_q8;
    double camera_y_q8;
    double relative_x_q8;
    double relative_y_q8;
    double alpha;
    double snapshot_interval_ms;
    int delta_x_q8;
    int delta_y_q8;
    int valid;
    int interpolated;
    int discontinuity;
} gw_camera_interpolation_result;

/* Pure interpolation over immutable camera samples. It never reads game RAM. */
void gw_camera_interpolate(const gw_camera_interpolation_input *input,
                           gw_camera_interpolation_result *result);

#endif
