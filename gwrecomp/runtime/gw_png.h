#ifndef GW_PNG_H
#define GW_PNG_H
/* Minimal, self-contained PNG reader for the optional HD terrain overrides (hd_textures/): zlib inflate (stored,
   fixed and dynamic Huffman blocks) and the five PNG row filters; 8-bit greyscale, grey+alpha, RGB, RGBA and
   palette images, not interlaced. Output: RGBA8, rows top to bottom. Returns NULL on anything else. No dependency
   beyond the C library, so the release keeps shipping SDL2.dll only. */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

typedef struct { const uint8_t *p,*e; uint32_t bits; int n; int err; } gwp_bits;
typedef struct { uint16_t count[16],sym[288]; } gwp_huff;

static int gwp_bit(gwp_bits *b,int need) {
    while(b->n<need) { if(b->p>=b->e) { b->err=1; return 0; } b->bits|=(uint32_t)*b->p++<<b->n; b->n+=8; }
    const int v=(int)(b->bits&((1u<<need)-1u)); b->bits>>=need; b->n-=need; return v;
}
static void gwp_build(gwp_huff *h,const uint8_t *len,int n) {
    uint16_t offs[16]; memset(h->count,0,sizeof h->count);
    for(int i=0;i<n;i++) h->count[len[i]]++;
    h->count[0]=0; offs[1]=0;
    for(int i=1;i<15;i++) offs[i+1]=(uint16_t)(offs[i]+h->count[i]);
    for(int i=0;i<n;i++) if(len[i]) h->sym[offs[len[i]]++]=(uint16_t)i;
}
static int gwp_decode(gwp_bits *b,const gwp_huff *h) {
    int code=0,first=0,index=0;
    for(int len=1;len<16;len++) {
        code|=gwp_bit(b,1); if(b->err) return -1;
        const int c=h->count[len];
        if(code-c<first) return h->sym[index+(code-first)];
        index+=c; first+=c; first<<=1; code<<=1;
    }
    b->err=1; return -1;
}
/* inflates a zlib stream into out (capacity cap); returns the bytes written or -1 */
static long gwp_inflate(const uint8_t *src,size_t n,uint8_t *out,size_t cap) {
    static const uint16_t lbase[29]={3,4,5,6,7,8,9,10,11,13,15,17,19,23,27,31,35,43,51,59,67,83,99,115,131,163,195,227,258};
    static const uint8_t lext[29]={0,0,0,0,0,0,0,0,1,1,1,1,2,2,2,2,3,3,3,3,4,4,4,4,5,5,5,5,0};
    static const uint16_t dbase[30]={1,2,3,4,5,7,9,13,17,25,33,49,65,97,129,193,257,385,513,769,1025,1537,2049,3073,4097,6145,8193,12289,16385,24577};
    static const uint8_t dext[30]={0,0,0,0,1,1,2,2,3,3,4,4,5,5,6,6,7,7,8,8,9,9,10,10,11,11,12,12,13,13};
    static const uint8_t ord[19]={16,17,18,0,8,7,9,6,10,5,11,4,12,3,13,2,14,1,15};
    if(n<2 || (src[0]&15)!=8 || ((src[0]<<8)|src[1])%31) return -1;
    gwp_bits b={src+2,src+n,0,0,0}; size_t o=0; int last=0;
    while(!last) {
        last=gwp_bit(&b,1); const int type=gwp_bit(&b,2); if(b.err) return -1;
        if(type==0) {
            b.bits=0; b.n=0;
            if(b.e-b.p<4) return -1;
            const unsigned len=b.p[0]|(b.p[1]<<8); b.p+=4;
            if((size_t)(b.e-b.p)<len || cap-o<len) return -1;
            memcpy(out+o,b.p,len); b.p+=len; o+=len; continue;
        }
        gwp_huff lit,dist; uint8_t lens[320];
        if(type==1) {
            int i=0; for(;i<144;i++) lens[i]=8; for(;i<256;i++) lens[i]=9; for(;i<280;i++) lens[i]=7; for(;i<288;i++) lens[i]=8;
            gwp_build(&lit,lens,288); for(i=0;i<30;i++) lens[i]=5; gwp_build(&dist,lens,30);
        } else if(type==2) {
            const int nlen=gwp_bit(&b,5)+257,ndist=gwp_bit(&b,5)+1,ncode=gwp_bit(&b,4)+4;
            uint8_t cl[19]={0}; for(int i=0;i<ncode;i++) cl[ord[i]]=(uint8_t)gwp_bit(&b,3);
            gwp_huff ch; gwp_build(&ch,cl,19); int i=0;
            while(i<nlen+ndist) {
                int s=gwp_decode(&b,&ch); if(s<0) return -1;
                if(s<16) lens[i++]=(uint8_t)s;
                else { int rep,val=0;
                    if(s==16) { if(!i) return -1; val=lens[i-1]; rep=3+gwp_bit(&b,2); }
                    else if(s==17) rep=3+gwp_bit(&b,3); else rep=11+gwp_bit(&b,7);
                    if(i+rep>nlen+ndist) return -1;
                    while(rep--) lens[i++]=(uint8_t)val; }
                if(b.err) return -1;
            }
            gwp_build(&lit,lens,nlen); gwp_build(&dist,lens+nlen,ndist);
        } else return -1;
        for(;;) {
            int s=gwp_decode(&b,&lit); if(s<0) return -1;
            if(s<256) { if(o>=cap) return -1; out[o++]=(uint8_t)s; }
            else if(s==256) break;
            else { s-=257; if(s>=29) return -1;
                const size_t len=lbase[s]+(size_t)gwp_bit(&b,lext[s]);
                const int ds=gwp_decode(&b,&dist); if(ds<0 || ds>=30) return -1;
                const size_t d=dbase[ds]+(size_t)gwp_bit(&b,dext[ds]);
                if(b.err || d>o || cap-o<len) return -1;
                for(size_t k=0;k<len;k++,o++) out[o]=out[o-d]; }
        }
    }
    return (long)o;
}
static uint32_t gwp_be32(const uint8_t *p) { return ((uint32_t)p[0]<<24)|((uint32_t)p[1]<<16)|((uint32_t)p[2]<<8)|p[3]; }
static int gwp_paeth(int a,int b,int c) { const int p=a+b-c,pa=abs(p-a),pb=abs(p-b),pc=abs(p-c); return pa<=pb && pa<=pc?a:pb<=pc?b:c; }

/* loads path; *w,*h = size; returns malloc'd RGBA8 or NULL */
static uint8_t *gw_png_load(const char *path,int *w,int *h) {
    FILE *f=fopen(path,"rb"); if(!f) return NULL;
    fseek(f,0,SEEK_END); const long sz=ftell(f); fseek(f,0,SEEK_SET);
    if(sz<57 || sz>(64l<<20)) { fclose(f); return NULL; }
    uint8_t *file=(uint8_t *)malloc((size_t)sz); if(!file) { fclose(f); return NULL; }
    const size_t got=fread(file,1,(size_t)sz,f); fclose(f);
    uint8_t *idat=NULL,*raw=NULL,*rgba=NULL; size_t ni=0; uint8_t pal[1024]; memset(pal,255,sizeof pal);
    uint32_t W=0,H=0; int ct=-1;
    if(got!=(size_t)sz || memcmp(file,"\x89PNG\r\n\x1a\n",8)) goto done;
    idat=(uint8_t *)malloc((size_t)sz); if(!idat) goto done;
    for(size_t p=8;p+12<=(size_t)sz;) {
        const uint32_t len=gwp_be32(file+p); const uint8_t *t=file+p+4,*d=file+p+8;
        if(len>(size_t)sz-p-12) goto done;
        if(!memcmp(t,"IHDR",4) && len>=13) { W=gwp_be32(d); H=gwp_be32(d+4); ct=d[9];
            if(d[8]!=8 || d[10] || d[11] || d[12] || W==0 || H==0 || W>8192 || H>8192) goto done; }
        else if(!memcmp(t,"PLTE",4)) { for(uint32_t i=0;i<len/3 && i<256;i++) { pal[i*4]=d[i*3]; pal[i*4+1]=d[i*3+1]; pal[i*4+2]=d[i*3+2]; } }
        else if(!memcmp(t,"tRNS",4) && ct==3) { for(uint32_t i=0;i<len && i<256;i++) pal[i*4+3]=d[i]; }
        else if(!memcmp(t,"IDAT",4)) { memcpy(idat+ni,d,len); ni+=len; }
        else if(!memcmp(t,"IEND",4)) break;
        p+=12u+len;
    }
    {   const int ch=ct==0?1:ct==2?3:ct==3?1:ct==4?2:ct==6?4:0;
        if(!ch) goto done;
        const size_t stride=(size_t)W*ch,need=(stride+1u)*H;
        raw=(uint8_t *)malloc(need); rgba=(uint8_t *)malloc((size_t)W*H*4u);
        if(!raw || !rgba || gwp_inflate(idat,ni,raw,need)!=(long)need) { free(rgba); rgba=NULL; goto done; }
        for(uint32_t y=0;y<H;y++) {
            uint8_t *r=raw+y*(stride+1u)+1u; const uint8_t *u=y?raw+(y-1u)*(stride+1u)+1u:NULL; const int ft=r[-1];
            for(size_t x=0;x<stride;x++) {
                const int a=x>=(size_t)ch?r[x-ch]:0,b=u?u[x]:0,c=(u && x>=(size_t)ch)?u[x-ch]:0;
                switch(ft) { case 0: break; case 1: r[x]=(uint8_t)(r[x]+a); break; case 2: r[x]=(uint8_t)(r[x]+b); break;
                    case 3: r[x]=(uint8_t)(r[x]+((a+b)>>1)); break; case 4: r[x]=(uint8_t)(r[x]+gwp_paeth(a,b,c)); break;
                    default: free(rgba); rgba=NULL; goto done; }
            }
            uint8_t *o=rgba+(size_t)y*W*4u;
            for(uint32_t x=0;x<W;x++,o+=4) {
                const uint8_t *s=r+(size_t)x*ch;
                if(ct==0) { o[0]=o[1]=o[2]=s[0]; o[3]=255; }
                else if(ct==4) { o[0]=o[1]=o[2]=s[0]; o[3]=s[1]; }
                else if(ct==2) { o[0]=s[0]; o[1]=s[1]; o[2]=s[2]; o[3]=255; }
                else if(ct==6) memcpy(o,s,4);
                else memcpy(o,pal+(size_t)s[0]*4u,4);
            }
        }
        *w=(int)W; *h=(int)H;
    }
done:
    free(file); free(idat); free(raw);
    return rgba;
}
#endif
