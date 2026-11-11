#ifndef GW_CDDA_AUDIO_H
#define GW_CDDA_AUDIO_H

#include <stdint.h>

/* Optional host renderer for original MSCDEX CD-DA requests. The guest keeps
 * issuing and acknowledging its original commands; missing host audio only
 * degrades to silence. Track data is read from the user's configured CUE/BIN. */
void gw_cdda_set_volume(uint8_t channel0, uint8_t channel1,
                        uint8_t channel2, uint8_t channel3);
void gw_cdda_play(uint32_t start_lba, uint32_t sector_count, int repeat);
void gw_cdda_pause(void);
void gw_cdda_resume(void);
void gw_cdda_stop(void);
void gw_cdda_pump(void);
void gw_cdda_shutdown(void);

#endif
