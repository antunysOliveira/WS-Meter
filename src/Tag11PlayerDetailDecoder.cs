// ==================== tag=11 — Player detail (class + amp gear) ====================
//
// [MEDIDO 2026-09-22] via --probe-follow on 8 ENTER events across two captures
// (ws_20260922_094830 city, raid_deserto_boss_20260922_000054). Every tag=25
// body-5B ENTER for a player id is followed within ~200ms by a burst of frames
// inside a tag=492 container, and tag=11 (47 bytes fixed) reliably carries the
// class field. Samples:
//
//   msg#12 raid  id=0x0044A9DF  bytes[18..25] = 0a 08 09 09 0a 0a 09 00
//   msg#24 raid  id=0x00563057  bytes[18..25] = 08 08 07 08 00 06 09 00
//   msg#42 raid  id=0x006C3FCB  bytes[18..25] = 06 06 09 07 06 07 06 00
//   msg#19 raid  id=0x00551FD7  bytes[18..25] = 01 04 06 07 00 07 01 00
//   msg#22 raid  id=0x006A5937  bytes[18..25] = 07 05 0a 05 00 06 03 00
//   msg#14 city  Jakar=0x006A5BE5  bytes[18..25] = 07 05 0a 0a 00 0a 06 00
//   msg#12 city  Liba =0x004C5E64  bytes[18..25] = 04 05 05 05 00 05 04 00
//
// All byte-18 values sit in the class range 1..20. Bytes 19..25 look like
// amplification levels for equipment slots (values 0..10, common cap).
//
// Body layout (47 bytes):
//   [0..17]  18B header  — packed appearance/equipment data (not decoded here)
//   [18]     u8 class_id — 1..20, matches data/class-names.json ✓
//   [19..25] 7B          — amplification levels (INFERIDO)
//   [26..29] u32 LE      — entity_id
//   [30..46] 17B         — trailing state (not decoded)
//
// This replaces the memscan-only class source for players entering the
// observer's area. tag=11 fires on ENTER, so classe é populada assim que o
// jogador aparece — sem depender de renderização nem de scan de memória.
//
// Ghidra reader confirmation still pending (need FUN_006685d0 case 0x0b dump);
// classification is [MEDIDO] until [LIDO].

using System;
using System.Collections.Generic;

namespace WSEngine
{
    public static class Tag11PlayerDetailDecoder
    {
        const int Tag = 11;
        const int BodyLen = 47;
        const int ClassOffset = 18;
        const int IdOffset = 26;

        // Extract every (entity_id, class_id) pair from tag=11 messages in the
        // window. Runs top-level AND inside decompressed tag=492 containers.
        // Merges into `target` — never removes.
        internal static void Extract(IList<TlvMessage> messages, Dictionary<uint, int> target)
        {
            if (messages == null || target == null) return;
            for (int i = 0; i < messages.Count; i++)
            {
                var m = messages[i];
                if (m == null || m.Body == null) continue;

                if (m.Tag == Tag && m.Body.Length == BodyLen) Handle(m.Body, target);
                else if (m.Tag == 492 && m.Body.Length >= 5)
                {
                    byte[] dec = TryDecompress(m.Body);
                    if (dec == null) continue;
                    var seg = new TcpSegment { Time = m.Time, ClientToServer = false, Seq = 0, Payload = dec };
                    var inner = TlvSplit.Parse(new List<TcpSegment> { seg });
                    foreach (var im in inner.Messages)
                    {
                        if (im == null || im.Body == null) continue;
                        if (im.Tag == Tag && im.Body.Length == BodyLen) Handle(im.Body, target);
                    }
                }
            }
        }

        static void Handle(byte[] body, Dictionary<uint, int> target)
        {
            int classId = body[ClassOffset];
            if (classId < 1 || classId > 20) return;
            uint id = BitConverter.ToUInt32(body, IdOffset);
            if (id == 0) return;
            // Only overwrite if the current value is missing or zero. Preserves
            // other decoders' contributions (tag=551/554/207, memscan).
            int existing;
            if (!target.TryGetValue(id, out existing) || existing <= 0) target[id] = classId;
        }

        static byte[] TryDecompress(byte[] body)
        {
            try
            {
                int pos = 0;
                int N;
                if (!ReadVarint(body, ref pos, out N)) return null;
                if (N < 0 || pos + N + 4 > body.Length) return null;
                uint expected = BitConverter.ToUInt32(body, pos + N);
                if (expected > 10 * 1024 * 1024) return null;
                return Lz4.DecompressBlock(body, pos, N, (int)expected);
            }
            catch { return null; }
        }

        static bool ReadVarint(byte[] buf, ref int pos, out int val)
        {
            val = 0;
            int shift = 0;
            while (pos < buf.Length)
            {
                byte b = buf[pos++];
                val |= (b & 0x7F) << shift;
                if ((b & 0x80) == 0) return true;
                shift += 7;
                if (shift > 28) return false;
            }
            return false;
        }
    }
}
