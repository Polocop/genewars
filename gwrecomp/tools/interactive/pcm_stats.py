"""Windowed statistics of a captured s16 stereo PCM file (GW_VSB16_CAPTURE). Usage: pcm_stats.py file.pcm [rate] [window_s]"""
import sys, array, math
f = sys.argv[1]; rate = int(sys.argv[2]) if len(sys.argv) > 2 else 22050; win = float(sys.argv[3]) if len(sys.argv) > 3 else 1.0
a = array.array('h'); a.frombytes(open(f, 'rb').read()[: (len(open(f, 'rb').read()) // 4) * 4])
n = len(a) // 2; step = int(rate * win)
print(f"frames={n} duration={n/rate:.1f}s")
tot_sq = 0.0
for s in range(0, n - step + 1, step):
    seg = a[2 * s: 2 * (s + step)]
    l = seg[0::2]; r = seg[1::2]
    rms = math.sqrt(sum(x * x for x in l) / len(l)) / 32768
    pk = max(max(l), -min(l)) / 32768
    dc = sum(l) / len(l) / 32768
    zc = sum(1 for i in range(1, len(l)) if (l[i - 1] < 0) != (l[i] < 0)) / win
    print(f"t={s/rate:6.1f}s rms={rms:.4f} peak={pk:.3f} dc={dc:+.4f} zcr={zc:7.0f}/s")
