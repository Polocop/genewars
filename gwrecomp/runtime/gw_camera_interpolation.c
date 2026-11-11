#include "gw_camera_interpolation.h"

#include <stdlib.h>
#include <string.h>

static int camera_delta_shortest(int current,int previous) {
    int delta=current-previous;
    const int period=128*256;
    while(delta < -period/2) delta+=period;
    while(delta >= period/2) delta-=period;
    return delta;
}

void gw_camera_interpolate(const gw_camera_interpolation_input *input,
                           gw_camera_interpolation_result *result) {
    if(!result) return;
    memset(result,0,sizeof *result);
    result->alpha=1.0;
    if(!input || !input->current_valid) return;
    result->valid=1;
    result->camera_x_q8=(double)input->current_x_q8;
    result->camera_y_q8=(double)input->current_y_q8;
    if(!input->previous_valid) return;
    if(input->current_turn!=input->previous_turn+1u ||
       input->current_captured_at<=input->previous_captured_at ||
       !input->counter_frequency) {
        result->discontinuity=1;
        return;
    }
    const uint64_t interval=input->current_captured_at-input->previous_captured_at;
    const int dx=camera_delta_shortest(input->current_x_q8,input->previous_x_q8);
    const int dy=camera_delta_shortest(input->current_y_q8,input->previous_y_q8);
    result->delta_x_q8=dx;
    result->delta_y_q8=dy;
    if(interval>input->counter_frequency/8u || abs(dx)>2048 || abs(dy)>2048) {
        result->discontinuity=1;
        return;
    }
    const uint64_t target=input->now>interval?input->now-interval:0u;
    double alpha=target<=input->previous_captured_at?0.0:
        target>=input->current_captured_at?1.0:
        (double)(target-input->previous_captured_at)/(double)interval;
    if(alpha<0.0) alpha=0.0;
    if(alpha>1.0) alpha=1.0;
    result->alpha=alpha;
    result->relative_x_q8=-(double)dx*(1.0-alpha);
    result->relative_y_q8=-(double)dy*(1.0-alpha);
    result->camera_x_q8=(double)input->current_x_q8+result->relative_x_q8;
    result->camera_y_q8=(double)input->current_y_q8+result->relative_y_q8;
    result->snapshot_interval_ms=(double)interval*1000.0/(double)input->counter_frequency;
    result->interpolated=(dx!=0 || dy!=0) && alpha>0.0001 && alpha<0.9999;
}
