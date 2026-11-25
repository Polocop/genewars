#include <assert.h>
#include "gw_entity_coverage.h"

int main(void) {
    uint8_t pixels[18];
    gw_entity_coverage state;
    gw_entity_coverage_begin(&state,pixels,100,6,3,2);
    gw_entity_coverage_write(&state,102,3,2);
    gw_entity_coverage_write(&state,104,6,3);
    gw_entity_coverage_write(&state,103,2,0);
    gw_entity_coverage_write(&state,115,9,1);
    gw_entity_coverage_write(&state,118,1,9);
    const uint8_t expected[18]={0,0,2,0,0,3,0,0,3,3,0,0,0,0,0,1,1,1};
    assert(memcmp(pixels,expected,sizeof pixels)==0);
    gw_entity_coverage_begin(&state,pixels,200,6,3,2);
    gw_entity_coverage_write(&state,115,1,4);
    const uint8_t empty[18]={0};
    assert(memcmp(pixels,empty,sizeof pixels)==0);
}
