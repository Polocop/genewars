#define _CRT_SECURE_NO_WARNINGS
#include "gw_cdda_audio.h"

#include <SDL.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#define GW_CDDA_MAX_TRACKS 99u
#define GW_CDDA_SECTOR_BYTES 2352u
#define GW_CDDA_FRAMES_PER_SECOND 75u
#define GW_CDDA_RATE 44100
#define GW_CDDA_CHUNK_SECTORS 32u
#define GW_CDDA_QUEUE_TARGET_BYTES (GW_CDDA_RATE * 2u * 2u)
#define GW_CDDA_QUEUE_LOW_BYTES (GW_CDDA_RATE * 2u / 2u)

typedef struct gw_cdda_track {
    unsigned number;
    int audio;
    uint32_t lba_start;
    uint32_t sectors;
    uint32_t index01;
    char path[1024];
} gw_cdda_track;

typedef struct gw_cdda_state {
    SDL_AudioDeviceID device;
    SDL_mutex *mutex;
    SDL_AudioSpec obtained;
    gw_cdda_track tracks[GW_CDDA_MAX_TRACKS];
    unsigned track_count;
    uint8_t volume[4];
    int volume_received;
    uint32_t start_lba;
    uint32_t next_lba;
    uint32_t end_lba;
    uint32_t requests;
    uint64_t bytes_queued;
    uint32_t chunks_queued;
    int initialized;
    int route_available;
    int playing;
    int paused;
    int repeat;
    int pending_play;
    uint32_t pending_start_lba;
    uint32_t pending_sector_count;
    int pending_repeat;
    int pending_paused;
    int audio_subsystem_owned;
    char cue_path[1024];
    char error[256];
} gw_cdda_state;

static gw_cdda_state g_cdda;

static int gw_cdda_parse_msf(const char *text, uint32_t *frames) {
    unsigned minutes=0,seconds=0,subframes=0;
    char tail=0;
    if(!text || !frames || sscanf(text,"%u:%u:%u%c",&minutes,&seconds,&subframes,&tail)!=3 ||
       seconds>=60u || subframes>=GW_CDDA_FRAMES_PER_SECOND || minutes>99u) return 0;
    *frames=(uint32_t)(((uint64_t)minutes*60u+seconds)*GW_CDDA_FRAMES_PER_SECOND+subframes);
    return 1;
}

static int gw_cdda_finalize_track(gw_cdda_track *track,uint32_t *disc_lba) {
    struct _stat64 st;
    FILE *fp;
    int64_t size;
    if(!track || !disc_lba || !track->number || !track->path[0] || !track->index01) {
        /* INDEX 01 at 00:00:00 is valid; the number is the reliable sentinel. */
        if(!track || !disc_lba || !track->number || !track->path[0]) return 0;
    }
    if(_stat64(track->path,&st)!=0 || st.st_size<0 ||
       (uint64_t)st.st_size%GW_CDDA_SECTOR_BYTES!=0u) return 0;
    size=(int64_t)st.st_size;
    track->lba_start=*disc_lba;
    track->sectors=(uint32_t)((uint64_t)size/GW_CDDA_SECTOR_BYTES);
    if(track->index01>track->sectors || UINT32_MAX-*disc_lba<track->sectors) return 0;
    *disc_lba+=track->sectors;
    fp=fopen(track->path,"rb");
    if(!fp) return 0;
    fclose(fp);
    return 1;
}

static int gw_cdda_load_cue(const char *cue_path) {
    FILE *cue=NULL;
    char line[1200],directory[1024]="",current_file[1024]="";
    uint32_t disc_lba=0u;
    gw_cdda_track pending;
    int have_pending=0,ok=0;
    memset(&pending,0,sizeof pending);
    cue=fopen(cue_path,"rb");
    if(!cue) { snprintf(g_cdda.error,sizeof g_cdda.error,"cannot open CUE (errno=%d)",errno); return 0; }
    strncpy(g_cdda.cue_path,cue_path,sizeof g_cdda.cue_path-1u);
    const char *last_slash1=strrchr(cue_path,'\\');
    const char *last_slash2=strrchr(cue_path,'/');
    const char *last_slash=last_slash1;
    if(last_slash2 && (!last_slash || last_slash2>last_slash)) last_slash=last_slash2;
    if(last_slash) {
        size_t n=(size_t)(last_slash-cue_path);
        if(n>=sizeof directory) { snprintf(g_cdda.error,sizeof g_cdda.error,"CUE directory path is too long"); goto done; }
        memcpy(directory,cue_path,n); directory[n]='\0';
    }
    while(fgets(line,sizeof line,cue)) {
        char name[768],kind[32]; unsigned n=0;
        if(sscanf(line," FILE \"%767[^\"]\" %31s",name,kind)==2) {
            if(_stricmp(kind,"BINARY")!=0) { snprintf(g_cdda.error,sizeof g_cdda.error,"only BINARY CUE files are supported"); goto done; }
            if(have_pending) {
                if(g_cdda.track_count>=GW_CDDA_MAX_TRACKS ||
                   !gw_cdda_finalize_track(&pending,&disc_lba)) {
                    snprintf(g_cdda.error,sizeof g_cdda.error,"invalid or unaligned CUE track file"); goto done;
                }
                g_cdda.tracks[g_cdda.track_count++]=pending;
                memset(&pending,0,sizeof pending); have_pending=0;
            }
            if(directory[0]) {
                if(snprintf(current_file,sizeof current_file,"%s\\%s",directory,name)<0 ||
                   strlen(current_file)>=sizeof current_file-1u) {
                    snprintf(g_cdda.error,sizeof g_cdda.error,"CUE track path is too long"); goto done;
                }
            } else {
                if(strlen(name)>=sizeof current_file) { snprintf(g_cdda.error,sizeof g_cdda.error,"CUE track path is too long"); goto done; }
                strcpy(current_file,name);
            }
            continue;
        }
        if(sscanf(line," TRACK %u %31s",&n,kind)==2) {
            if(have_pending || !current_file[0] || n<1u || n>99u) {
                snprintf(g_cdda.error,sizeof g_cdda.error,"unsupported multi-track FILE or invalid TRACK entry"); goto done;
            }
            memset(&pending,0,sizeof pending); pending.number=n;
            pending.audio=_stricmp(kind,"AUDIO")==0;
            if(!pending.audio && _strnicmp(kind,"MODE1/",6)!=0) {
                snprintf(g_cdda.error,sizeof g_cdda.error,"unsupported CUE track mode"); goto done;
            }
            strcpy(pending.path,current_file); have_pending=1;
            continue;
        }
        if(have_pending && sscanf(line," INDEX 01 %31s",kind)==1) {
            if(!gw_cdda_parse_msf(kind,&pending.index01)) {
                snprintf(g_cdda.error,sizeof g_cdda.error,"invalid INDEX 01 timestamp"); goto done;
            }
        }
    }
    if(ferror(cue)) { snprintf(g_cdda.error,sizeof g_cdda.error,"error reading CUE"); goto done; }
    if(have_pending) {
        if(g_cdda.track_count>=GW_CDDA_MAX_TRACKS || !gw_cdda_finalize_track(&pending,&disc_lba)) {
            snprintf(g_cdda.error,sizeof g_cdda.error,"invalid final CUE track"); goto done;
        }
        g_cdda.tracks[g_cdda.track_count++]=pending;
    }
    if(!g_cdda.track_count) { snprintf(g_cdda.error,sizeof g_cdda.error,"CUE has no tracks"); goto done; }
    ok=1;
done:
    fclose(cue);
    if(!ok) g_cdda.track_count=0u;
    return ok;
}

static int gw_cdda_initialize(void) {
    const char *cue_path;
    SDL_AudioSpec wanted;
    if(g_cdda.initialized) return g_cdda.route_available;
    /* The guest may request CD audio before the interactive loop initializes SDL. */
    if(SDL_WasInit(0u)==0u) return 0;
    g_cdda.initialized=1;
    g_cdda.mutex=SDL_CreateMutex();
    if(!g_cdda.mutex) {
        snprintf(g_cdda.error,sizeof g_cdda.error,"SDL mutex: %s",SDL_GetError());
        fprintf(stderr,"TRACE CDDA disabled reason='%s'\n",g_cdda.error); return 0;
    }
    cue_path=getenv("GW_CD_AUDIO_CUE");
    if(!cue_path || !cue_path[0]) {
        snprintf(g_cdda.error,sizeof g_cdda.error,"GW_CD_AUDIO_CUE is not configured");
        fprintf(stderr,"TRACE CDDA disabled reason='%s' silence_fallback=1\n",g_cdda.error); return 0;
    }
    if(!gw_cdda_load_cue(cue_path)) {
        fprintf(stderr,"TRACE CDDA disabled CUE='%s' reason='%s' silence_fallback=1\n",cue_path,g_cdda.error); return 0;
    }
    if(!(SDL_WasInit(SDL_INIT_AUDIO)&SDL_INIT_AUDIO)) {
        if(SDL_InitSubSystem(SDL_INIT_AUDIO)!=0) {
            snprintf(g_cdda.error,sizeof g_cdda.error,"SDL audio subsystem: %s",SDL_GetError());
            fprintf(stderr,"TRACE CDDA disabled reason='%s' silence_fallback=1\n",g_cdda.error); return 0;
        }
        g_cdda.audio_subsystem_owned=1;
    }
    SDL_zero(wanted);
    wanted.freq=GW_CDDA_RATE; wanted.format=AUDIO_S16LSB; wanted.channels=2u;
    wanted.samples=4096u; wanted.callback=NULL;
    g_cdda.device=SDL_OpenAudioDevice(NULL,0,&wanted,&g_cdda.obtained,0u);
    if(!g_cdda.device) {
        snprintf(g_cdda.error,sizeof g_cdda.error,"SDL_OpenAudioDevice: %s",SDL_GetError());
        fprintf(stderr,"TRACE CDDA disabled CUE='%s' reason='%s' silence_fallback=1\n",cue_path,g_cdda.error); return 0;
    }
    if(g_cdda.obtained.freq!=wanted.freq || g_cdda.obtained.format!=wanted.format ||
       g_cdda.obtained.channels!=wanted.channels) {
        snprintf(g_cdda.error,sizeof g_cdda.error,"audio device did not accept 44100 Hz stereo S16LE");
        SDL_CloseAudioDevice(g_cdda.device); g_cdda.device=0u;
        fprintf(stderr,"TRACE CDDA disabled reason='%s' silence_fallback=1\n",g_cdda.error); return 0;
    }
    g_cdda.route_available=1;
    if(!g_cdda.volume_received) for(unsigned i=0;i<4u;i++) g_cdda.volume[i]=255u;
    SDL_PauseAudioDevice(g_cdda.device,1);
    fprintf(stderr,"TRACE CDDA ready cue='%s' tracks=%u driver='%s' device=%u format=S16LE rate=%d channels=2\n",
        g_cdda.cue_path,g_cdda.track_count,SDL_GetCurrentAudioDriver()?SDL_GetCurrentAudioDriver():"unknown",
        (unsigned)g_cdda.device,g_cdda.obtained.freq);
    return 1;
}

void gw_cdda_set_volume(uint8_t channel0,uint8_t channel1,uint8_t channel2,uint8_t channel3) {
    if(!g_cdda.initialized && SDL_WasInit(0u)==0u) {
        g_cdda.volume[0]=channel0; g_cdda.volume[1]=channel1;
        g_cdda.volume[2]=channel2; g_cdda.volume[3]=channel3;
        g_cdda.volume_received=1;
        fprintf(stderr,"TRACE CDDA volume deferred channels=%u/%u/%u/%u\n",
            channel0,channel1,channel2,channel3);
        return;
    }
    if(!gw_cdda_initialize()) return;
    SDL_LockMutex(g_cdda.mutex);
    g_cdda.volume[0]=channel0; g_cdda.volume[1]=channel1;
    g_cdda.volume[2]=channel2; g_cdda.volume[3]=channel3;
    g_cdda.volume_received=1;
    SDL_UnlockMutex(g_cdda.mutex);
    fprintf(stderr,"TRACE CDDA volume channels=%u/%u/%u/%u\n",
        channel0,channel1,channel2,channel3);
}

static const gw_cdda_track *gw_cdda_find_track(uint32_t lba) {
    for(unsigned i=0;i<g_cdda.track_count;i++) {
        const gw_cdda_track *t=&g_cdda.tracks[i];
        if(lba>=t->lba_start && (uint64_t)lba<(uint64_t)t->lba_start+t->sectors) return t;
    }
    return NULL;
}

void gw_cdda_play(uint32_t start_lba,uint32_t sector_count,int repeat) {
    uint64_t end=(uint64_t)start_lba+sector_count;
    const gw_cdda_track *first;
    if(!g_cdda.initialized && SDL_WasInit(0u)==0u) {
        g_cdda.pending_play=1;
        g_cdda.pending_start_lba=start_lba;
        g_cdda.pending_sector_count=sector_count;
        g_cdda.pending_repeat=repeat!=0;
        fprintf(stderr,"TRACE CDDA play deferred start_lba=%u sectors=%u repeat=%d reason=sdl-not-initialized\n",
            start_lba,sector_count,repeat!=0);
        return;
    }
    if(!gw_cdda_initialize()) return;
    first=gw_cdda_find_track(start_lba);
    if(!sector_count || end>UINT32_MAX || !first || !first->audio || start_lba<first->lba_start+first->index01) {
        fprintf(stderr,"TRACE CDDA play rejected start=%u sectors=%u reason=not-a-configured-audio-range\n",
            start_lba,sector_count); return;
    }
    /* A command may span the end-of-track pregap into the following contiguous
       AUDIO track, as the original game does. It may never cross a data track. */
    uint32_t cursor=start_lba;
    while((uint64_t)cursor<end) {
        const gw_cdda_track *t=gw_cdda_find_track(cursor);
        if(!t || !t->audio) {
            fprintf(stderr,"TRACE CDDA play rejected start=%u sectors=%u at_lba=%u reason=range-crosses-non-audio\n",
                start_lba,sector_count,cursor); return;
        }
        uint64_t next=(uint64_t)t->lba_start+t->sectors;
        if(next>=end) break;
        if(next>UINT32_MAX) return;
        cursor=(uint32_t)next;
    }
    SDL_LockMutex(g_cdda.mutex);
    SDL_ClearQueuedAudio(g_cdda.device);
    g_cdda.start_lba=start_lba; g_cdda.next_lba=start_lba; g_cdda.end_lba=(uint32_t)end;
    g_cdda.repeat=repeat!=0; g_cdda.playing=1; g_cdda.paused=0; g_cdda.requests++;
    g_cdda.bytes_queued=0u; g_cdda.chunks_queued=0u;
    SDL_PauseAudioDevice(g_cdda.device,0);
    SDL_UnlockMutex(g_cdda.mutex);
    fprintf(stderr,"TRACE CDDA play accepted request=%u start_lba=%u sectors=%u track=%u repeat=%u\n",
        g_cdda.requests,start_lba,sector_count,first->number,g_cdda.repeat);
}

void gw_cdda_pause(void) {
    if(!g_cdda.route_available || !g_cdda.device) {
        if(g_cdda.pending_play) g_cdda.pending_paused=1;
        return;
    }
    SDL_LockMutex(g_cdda.mutex);
    if(g_cdda.playing) { g_cdda.paused=1; SDL_PauseAudioDevice(g_cdda.device,1); }
    SDL_UnlockMutex(g_cdda.mutex);
    fprintf(stderr,"TRACE CDDA pause queued_bytes=%u\n",SDL_GetQueuedAudioSize(g_cdda.device));
}

void gw_cdda_resume(void) {
    if(!g_cdda.route_available || !g_cdda.device) {
        if(g_cdda.pending_play) g_cdda.pending_paused=0;
        return;
    }
    SDL_LockMutex(g_cdda.mutex);
    if(g_cdda.paused && g_cdda.playing) { g_cdda.paused=0; SDL_PauseAudioDevice(g_cdda.device,0); }
    SDL_UnlockMutex(g_cdda.mutex);
    fprintf(stderr,"TRACE CDDA resume playing=%d queued_bytes=%u\n",g_cdda.playing,
        SDL_GetQueuedAudioSize(g_cdda.device));
}

void gw_cdda_stop(void) {
    if(!g_cdda.route_available || !g_cdda.device) {
        g_cdda.pending_play=0; g_cdda.pending_paused=0;
        return;
    }
    SDL_LockMutex(g_cdda.mutex);
    SDL_ClearQueuedAudio(g_cdda.device);
    g_cdda.playing=0; g_cdda.paused=0; g_cdda.repeat=0;
    SDL_UnlockMutex(g_cdda.mutex);
    fprintf(stderr,"TRACE CDDA stop queue_cleared=1\n");
}

static int16_t gw_cdda_saturate(int32_t value) {
    if(value>32767) value=32767;
    if(value<-32768) value=-32768;
    return (int16_t)value;
}

void gw_cdda_pump(void) {
    static int first_pump_logged=0;
    uint8_t raw[GW_CDDA_SECTOR_BYTES*GW_CDDA_CHUNK_SECTORS];
    uint8_t out[GW_CDDA_SECTOR_BYTES*GW_CDDA_CHUNK_SECTORS];
    if(!first_pump_logged) {
        first_pump_logged=1;
        fprintf(stderr,"TRACE CDDA pump_entered\n");
    }
    if(!g_cdda.initialized) (void)gw_cdda_initialize();
    if(!g_cdda.route_available || !g_cdda.device || !g_cdda.mutex) return;
    if(g_cdda.pending_play) {
        const uint32_t start=g_cdda.pending_start_lba;
        const uint32_t count=g_cdda.pending_sector_count;
        const int repeat=g_cdda.pending_repeat;
        const int paused=g_cdda.pending_paused;
        g_cdda.pending_play=0;
        gw_cdda_play(start,count,repeat);
        if(paused) gw_cdda_pause();
        g_cdda.pending_paused=0;
    }
    SDL_LockMutex(g_cdda.mutex);
    if(!g_cdda.playing || g_cdda.paused || SDL_GetQueuedAudioSize(g_cdda.device)>=GW_CDDA_QUEUE_TARGET_BYTES) {
        static int first_idle_logged=0;
        if(!first_idle_logged) {
            first_idle_logged=1;
            fprintf(stderr,"TRACE CDDA pump_idle playing=%d paused=%d queue_bytes=%u next_lba=%u end_lba=%u\n",
                g_cdda.playing,g_cdda.paused,SDL_GetQueuedAudioSize(g_cdda.device),
                g_cdda.next_lba,g_cdda.end_lba);
        }
        SDL_UnlockMutex(g_cdda.mutex); return;
    }
    if(SDL_GetQueuedAudioSize(g_cdda.device)>=GW_CDDA_QUEUE_LOW_BYTES) {
        SDL_UnlockMutex(g_cdda.mutex); return;
    }
    unsigned chunks=0u;
    while(chunks<4u && SDL_GetQueuedAudioSize(g_cdda.device)<GW_CDDA_QUEUE_TARGET_BYTES) {
        if(g_cdda.next_lba>=g_cdda.end_lba) {
            if(g_cdda.repeat) g_cdda.next_lba=g_cdda.start_lba;
            else { g_cdda.playing=0; break; }
        }
        const gw_cdda_track *track=gw_cdda_find_track(g_cdda.next_lba);
        if(!track || !track->audio) { g_cdda.playing=0; break; }
        uint32_t track_end=track->lba_start+track->sectors;
        uint32_t sectors=(uint32_t)(sizeof raw/GW_CDDA_SECTOR_BYTES);
        if(track_end-g_cdda.next_lba<sectors) sectors=track_end-g_cdda.next_lba;
        if(g_cdda.end_lba-g_cdda.next_lba<sectors) sectors=g_cdda.end_lba-g_cdda.next_lba;
        if(!sectors) { g_cdda.playing=0; break; }
        FILE *fp=fopen(track->path,"rb");
        if(!fp) {
            g_cdda.playing=0; snprintf(g_cdda.error,sizeof g_cdda.error,"cannot open audio track");
            fprintf(stderr,"TRACE CDDA read_failed lba=%u path='%s' reason=fopen\n",g_cdda.next_lba,track->path);
            break;
        }
        uint64_t offset=(uint64_t)(g_cdda.next_lba-track->lba_start)*GW_CDDA_SECTOR_BYTES;
        const int seek_ok=offset<=INT64_MAX && _fseeki64(fp,(int64_t)offset,SEEK_SET)==0;
        size_t bytes=(size_t)sectors*GW_CDDA_SECTOR_BYTES;
        const size_t got=seek_ok?fread(raw,1u,bytes,fp):0u;
        fclose(fp);
        if(got!=bytes) {
            g_cdda.playing=0; snprintf(g_cdda.error,sizeof g_cdda.error,"short CDDA track read");
            fprintf(stderr,"TRACE CDDA read_failed lba=%u expected=%u got=%u path='%s'\n",
                g_cdda.next_lba,(unsigned)bytes,(unsigned)got,track->path);
            break;
        }
        memcpy(out,raw,bytes);
        const uint8_t v0=g_cdda.volume[0],v1=g_cdda.volume[1],v2=g_cdda.volume[2],v3=g_cdda.volume[3];
        for(size_t i=0;i<bytes;i+=4u) {
            const int16_t left=(int16_t)((uint16_t)raw[i]<<8|raw[i+1u]);
            const int16_t right=(int16_t)((uint16_t)raw[i+2u]<<8|raw[i+3u]);
            /* MSCDEX channels route input L to output L/R, then input R to L/R. */
            const int32_t mixed_left=((int32_t)left*v0+(int32_t)right*v2)/255;
            const int32_t mixed_right=((int32_t)left*v1+(int32_t)right*v3)/255;
            const uint16_t out_left=(uint16_t)gw_cdda_saturate(mixed_left);
            const uint16_t out_right=(uint16_t)gw_cdda_saturate(mixed_right);
            out[i]=(uint8_t)out_left; out[i+1u]=(uint8_t)(out_left>>8);
            out[i+2u]=(uint8_t)out_right; out[i+3u]=(uint8_t)(out_right>>8);
        }
        if(SDL_QueueAudio(g_cdda.device,out,(uint32_t)bytes)!=0) {
            snprintf(g_cdda.error,sizeof g_cdda.error,"SDL_QueueAudio: %s",SDL_GetError());
            fprintf(stderr,"TRACE CDDA queue_failed error='%s'\n",SDL_GetError());
            g_cdda.playing=0; break;
        }
        g_cdda.next_lba+=sectors; g_cdda.bytes_queued+=bytes;
        g_cdda.chunks_queued++; chunks++;
    }
    const uint32_t queued=SDL_GetQueuedAudioSize(g_cdda.device);
    const uint64_t total=g_cdda.bytes_queued;
    const uint32_t n=g_cdda.chunks_queued;
    SDL_UnlockMutex(g_cdda.mutex);
    if(n && (n==chunks || queued)) {
        static uint32_t last_reported_chunks=0u;
        if(n!=last_reported_chunks) {
            last_reported_chunks=n;
            fprintf(stderr,"TRACE CDDA samples_queued chunks=%u total_bytes=%llu current_queue_bytes=%u driver='%s'\n",
                n,(unsigned long long)total,queued,
                SDL_GetCurrentAudioDriver()?SDL_GetCurrentAudioDriver():"unknown");
        }
    }
}

void gw_cdda_shutdown(void) {
    if(g_cdda.device) {
        SDL_ClearQueuedAudio(g_cdda.device);
        SDL_CloseAudioDevice(g_cdda.device); g_cdda.device=0u;
        fprintf(stderr,"TRACE CDDA shutdown device_closed=1 bytes_submitted=%llu requests=%u\n",
            (unsigned long long)g_cdda.bytes_queued,g_cdda.requests);
    }
    if(g_cdda.mutex) { SDL_DestroyMutex(g_cdda.mutex); g_cdda.mutex=NULL; }
    if(g_cdda.audio_subsystem_owned) { SDL_QuitSubSystem(SDL_INIT_AUDIO); g_cdda.audio_subsystem_owned=0; }
    g_cdda.route_available=0; g_cdda.playing=0; g_cdda.paused=0;
}
