// ==================== tag=99 Heal Decoder (LZ4-aware) ====================
//
// Individual heal event decoder.
//
// [LIDO] Reader FUN_0065db40 (vtable 0xc0e978) decompiled 2026-09-21:
//   +0   u8  bool  (crit flag — [INFERIDO], 14/231 records set on
//                    ws_20260920_212612 ≈ 6% consistent with crit rate)
//   +1   u32 amount (RAW heal amount, pre-overheal)
//   +5   u32 src (healer entity_id, player 0x00xxxxxx or pet 0x05xxxxxx)
//   +9   u32 tgt (heal target entity_id)
// Wire body length: 13 bytes (server version >= 0x895ff8, current 13.4.3).
//
// [MEDIDO] Validation against tag=554 u32[1] (heal_received_effective) on
// ws_20260920_212612: sum(amount) by TGT matches EXATO for 4/10 players
// (those with zero overheal); remaining 6 exceed placar by the overheal delta:
//   Centablg Δ=+2516 (raw 19046 vs eff 16530)
//   Lingyoo  Δ=+3244 (raw 8969 vs eff 5725)
//   Nfps     Δ=+4159 (raw 6270 vs eff 2111)
//   Sacrum   Δ=+145, Lbicare Δ=+903, Kreitols Δ=+83
// Delta always positive → confirms amount@1 is pre-overheal RAW.
//
// Nested inside tag=492 LZ4 container using same TLV walk as damage decoder.

using System;
using System.Collections.Generic;

namespace WSEngine
{
    internal struct HealEvent
    {
        public uint Amount;
        public uint SourceId;
        public uint TargetId;
        public bool IsCrit;
        public double Time;
    }

    internal class Tag99HealDecoder
    {
        const int HealTag = 99;
        const int HealBodyLength = 13;
        internal const int ScoreboardMinUncompressedBytes = 4800;

        internal event Action<HealEvent> OnHeal;

        public int Bodies492Total;
        public int Bodies492DecompOk;
        public int Bodies492DecompFail;

        internal void Feed(IList<TlvMessage> messages, DateTime frameTime)
        {
            if (messages == null) return;
            for (int i = 0; i < messages.Count; i++)
            {
                var m = messages[i];
                if (m == null) continue;
                if (m.Tag == HealTag && m.Body != null && m.Body.Length == HealBodyLength)
                {
                    Emit(m.Time, m.Body, 0);
                    continue;
                }
                if (m.Tag == 492 && m.Body != null && m.Body.Length >= 5)
                {
                    ParseContainer(m.Body, m.Time);
                }
            }
        }

        void ParseContainer(byte[] body, double msgTime)
        {
            Bodies492Total++;
            int pos = 0;
            int N;
            if (!ReadVarint(body, ref pos, out N)) return;
            if (N < 0 || pos + N + 4 != body.Length) return;
            int trailerOff = pos + N;
            uint expected = BitConverter.ToUInt32(body, trailerOff);
            if (expected > 10 * 1024 * 1024) return;

            byte[] decompressed;
            try
            {
                decompressed = Lz4.DecompressBlock(body, pos, N, (int)expected);
                Bodies492DecompOk++;
            }
            catch
            {
                Bodies492DecompFail++;
                return;
            }

            if (decompressed.Length >= ScoreboardMinUncompressedBytes) return;

            var seg = new TcpSegment { Time = msgTime, ClientToServer = false, Seq = 0, Payload = decompressed };
            var res = TlvSplit.Parse(new List<TcpSegment> { seg });
            foreach (var sub in res.Messages)
            {
                if (sub.Tag == HealTag && sub.Body != null && sub.Body.Length == HealBodyLength)
                {
                    Emit(msgTime, sub.Body, 0);
                }
            }
        }

        void Emit(double msgTime, byte[] buf, int off)
        {
            bool crit = buf[off + 0] != 0;
            uint amount = BitConverter.ToUInt32(buf, off + 1);
            uint src    = BitConverter.ToUInt32(buf, off + 5);
            uint tgt    = BitConverter.ToUInt32(buf, off + 9);
            if (src == 0 || amount == 0) return;
            var h = OnHeal;
            if (h != null) h(new HealEvent
            {
                Amount = amount,
                SourceId = src,
                TargetId = tgt,
                IsCrit = crit,
                Time = msgTime,
            });
        }

        static bool ReadVarint(byte[] b, ref int pos, out int val)
        {
            val = 0;
            int shift = 0;
            for (int i = 0; i < 5; i++)
            {
                if (pos >= b.Length) return false;
                byte x = b[pos++];
                val |= (x & 0x7f) << shift;
                if ((x & 0x80) == 0) return true;
                shift += 7;
            }
            return false;
        }
    }
}
