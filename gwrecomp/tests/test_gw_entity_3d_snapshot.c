#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "gw_entity_3d.h"

enum { GUEST_BYTES=0x03002000 };

int main(int argc,char **argv) {
    if(argc!=2) return 2;
    FILE *f=fopen(argv[1],"rb");
    if(!f) return 3;
    char magic[8];
    uint8_t *memory=malloc(GUEST_BYTES);
    if(!memory || fread(magic,1,sizeof magic,f)!=sizeof magic ||
       memcmp(magic,"GWSNAP2",7) || fseek(f,-GUEST_BYTES,SEEK_END) ||
       fread(memory,1,GUEST_BYTES,f)!=GUEST_BYTES) {
        free(memory);
        fclose(f);
        return 4;
    }
    fclose(f);
    gw_entity_3d_snapshot snapshot;
    if(!gw_entity_3d_read(memory,GUEST_BYTES,&snapshot)) {
        free(memory);
        return 5;
    }
    puts("guest_address,type,owner,world_x_q8,world_y_q8,ground_q6,world_z_q6,z_valid");
    for(size_t i=0;i<snapshot.count;i++) {
        const gw_entity_3d_t *e=&snapshot.entities[i];
        printf("%08x,%u,%u,%d,%d,%d,%d,%u\n",e->guest_address,(unsigned)e->type,(unsigned)e->owner,
               e->world_x_q8,e->world_y_q8,e->ground_q6,e->world_z_q6,(unsigned)e->z_valid);
    }
    free(memory);
    return 0;
}
