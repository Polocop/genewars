"""Compare two PE executables section by section, ignoring the symbol table and the build timestamp.

usage: python compare_executables.py A.exe B.exe
Reports, per section, size and SHA-256 equality, and whether the headers match apart from TimeDateStamp/CheckSum and the
COFF symbol-table pointers. Used to show that builds that differ only in symbol names produce the same machine code and data.
"""
import hashlib, struct, sys

def load(path):
    b = open(path, "rb").read()
    pe = struct.unpack_from("<I", b, 0x3C)[0]
    nsec, = struct.unpack_from("<H", b, pe + 6); opt = struct.unpack_from("<H", b, pe + 20)[0]
    sec0 = pe + 24 + opt
    secs = []
    for i in range(nsec):
        o = sec0 + 40 * i
        name = b[o:o + 8].rstrip(b"\0").decode("latin-1"); vsize, vaddr, rsize, rptr = struct.unpack_from("<IIII", b, o + 8)
        secs.append((name, vsize, vaddr, rsize, rptr, hashlib.sha256(b[rptr:rptr + rsize]).hexdigest() if rptr else "-"))
    return b, pe, secs

def main():
    a, pa, sa = load(sys.argv[1]); b, pb, sb = load(sys.argv[2])
    print("size:", len(a), len(b))
    same = True
    for x, y in zip(sa, sb):
        eq = x[:5] == y[:5] and x[5] == y[5]
        same &= eq
        print("%-8s vsize=%-8d raw=%-8d %s" % (x[0], x[1], x[3], "IDENTICAL" if eq else "DIFFERS (%s vs %s)" % (x[5][:10], y[5][:10])))
    same &= len(sa) == len(sb)
    print("all sections identical:", same)
    # headers: compare with timestamp/checksum/symbol-table pointer fields masked
    def masked(b, pe):
        h = bytearray(b[:sa[0][4] if sa else 0x400]);
        for off, n in ((pe + 8, 4), (pe + 12, 4), (pe + 16, 4), (pe + 24 + 64, 4)):
            h[off:off + n] = b"\0" * n
        return bytes(h)
    print("headers identical (TimeDateStamp, symbol-table pointer/count, CheckSum masked):", masked(a, pa) == masked(b, pb))
    sys.exit(0 if same else 1)
if __name__ == "__main__":
    main()
