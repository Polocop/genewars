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
/* enhanced_audio (play mode): shorter queue and music ducking (-30 %, ~300 ms ramps) while speech plays. */
void gw_cdda_set_enhanced(int on);
void gw_cdda_set_duck(int on);
float gw_cdda_gain(void);              /* current ducking gain (QA trace) */
/* music_volume (gwrecomp.ini, 0..100): host output gain of the CD music; the guest's own MSCDEX volume is untouched */
void gw_cdda_set_user_volume(int percent);
double gw_cdda_take_rms(void);          /* QA: RMS of the queued output since the last call (0..1), -1 when nothing queued */
const char *gw_cdda_status(void);      /* playing/paused/queued bytes (QA trace) */

#endif
