// ==================== tag=10 — Player class broadcast (open-world source) ====================
//
// [MEDIDO 2026-09-22 confirmed] Cross-checked against the tag=554 scoreboard
// of ws_20260920_212612 (10 known players). Result: 7/7 tag=10 hits landed
// the CORRECT class byte at offset 4. 0 mismatches. Remaining 3 gt players
// (Centablg observer + Lingyoo/Marcao) simply had no tag=10 in the window.
//
// Body layout (12 bytes fixed):
//   [0..3]   u32 LE  entity_id
//   [4]      u8      class_id (1..20)
//   [5]      u8      weapon_type? (varies 01/02/04)
//   [6]      u8      = 0x01 always in samples
//   [7]      u8      flags (usually 01, occasionally 00)
//   [8..9]   u16 LE  ? (varies)
//   [10..11] u16 LE  ? (varies)
//
// Sample bodies from ws_20260920_212612:
//   bc a0 48 00 04 02 01 01 48 00 0d 00  → Lbicare  class=4
//   72 5d 65 00 0b 04 01 00 a6 00 19 00  → Nfps     class=11
//   4f 5c 21 00 0c 04 01 01 82 00 03 00  → Kreitols class=12
//   ee 30 0b 00 02 01 01 00 66 01 04 00  → Exorcistty class=2
//   a2 5d 46 00 11 01 01 01 36 00 22 00  → Wander   class=17
//   2c 04 48 00 11 01 01 01 0d 00 11 00  → Sacrum   class=17
//   b6 0d 5f 00 01 01 01 01 79 00 12 00  → Peladehnho class=1
//
// tag=10 is broadcast by the server for every player in the observer's area.
// raid_overgod capture had 147 unique tag=10 ids (vs 22 via memscan) — this
// is THE source we were looking for for open-world class resolution.
//
// Volume: 380 hits inside 492-body + 17 top-level per protocol census across
// six pcaps. Fires per-player on visibility / area load.

using System;
using System.Collections.Generic;

namespace WSEngine
{
    public static class Tag10PlayerClassDecoder
    {
        const int Tag = 10;
        const int BodyLen = 12;
        const int IdOffset = 0;
        const int ClassOffset = 4;

        // Additive merge — writes only when id is missing OR current value is 0.
        // Priority ladder keeps 554/551 above this; those overwrite via their own
        // callers. tag=10 overwrites memscan/PlayerResolver values (protocol source).
        internal static void Extract(IList<TlvMessage> messages, Dictionary<uint, int> classMap)
        {
            if (messages == null || classMap == null) return;
            for (int i = 0; i < messages.Count; i++)
            {
                var m = messages[i];
                if (m == null || m.Body == null) continue;

                if (m.Tag == Tag && m.Body.Length == BodyLen) Handle(m.Body, classMap);
                else if (m.Tag == 492 && m.Body.Length >= 5)
                {
                    byte[] dec = TryDecompress(m.Body);
                    if (dec == null) continue;
                    var seg = new TcpSegment { Time = m.Time, ClientToServer = false, Seq = 0, Payload = dec };
                    var inner = TlvSplit.Parse(new List<TcpSegment> { seg });
                    foreach (var im in inner.Messages)
                        if (im != null && im.Body != null && im.Tag == Tag && im.Body.Length == BodyLen)
                            Handle(im.Body, classMap);
                }
            }
        }

        static void Handle(byte[] body, Dictionary<uint, int> classMap)
        {
            uint id = BitConverter.ToUInt32(body, IdOffset);
            if (id == 0 || (id >> 24) != 0x00 || id < 0x00010000) return;
            byte cls = body[ClassOffset];
            if (cls < 1 || cls > 20) return;
            classMap[id] = cls;   // overwrite — protocol beats memscan/resolver
        }

        static byte[] TryDecompress(byte[] body)
        {
            try
            {
                int pos = 0; int N;
                if (!ReadVarint(body, ref pos, out N)) return null;
                if (N < 0 || pos + N + 4 > body.Length) return null;
                uint expected = BitConverter.ToUInt32(body, pos + N);
                if (expected > 10 * 1024 * 1024) return null;
                return Lz4.DecompressBlock(body, pos, N, (int)expected);
            }
            catch { return null; }
        }

        static bool ReadVarint(byte[] b, ref int pos, out int val)
        {
            val = 0; int shift = 0;
            while (pos < b.Length)
            {
                byte x = b[pos++];
                val |= (x & 0x7F) << shift;
                if ((x & 0x80) == 0) return true;
                shift += 7;
                if (shift > 28) return false;
            }
            return false;
        }
    }
}
