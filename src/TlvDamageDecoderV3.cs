// ==================== V3 Damage Decoder (LZ4-aware) ====================
//
// Wire tag=492 body:
//   [varint N] [N bytes LZ4 compressed] [u32 uncompressed_size]
//
// After LZ4 decompress, content is a plain TLV stream (varint tag + varint len + body)
// using the same wire message classes as top-level. Each tag=427 record inside has the
// SAME 13-byte layout as top-level:
//   [u32 dmg][u32 att][u32 tgt][u8 flag]
//
// Confirmed by static RE (docs/CLIENT-RE-R5.md) and validated: 1314/1314 bodies from
// group-fight dump decompress with exact size match + walk zero orphan bytes.

using System;
using System.Collections.Generic;

namespace WSEngine
{
    internal struct DamageEvent
    {
        public uint Amount;
        public uint AttackerId;
        public uint TargetId;
        public byte Flag;
        public bool IsCrit;
        public double Time;
    }

    internal class TlvDamageDecoderV3
    {
        const int DamageTag = 427;
        const int DamageBodyLength = 13;
        // 492 message with uncompressed content >= ScoreboardMinBytes is the end-of-instance
        // scoreboard packet. Excluded from real-time damage sum.
        internal const int ScoreboardMinUncompressedBytes = 4800;

        internal event Action<DamageEvent> OnDamage;

        // Fidelity stats
        public int Bodies492Total;
        public int Bodies492DecompOk;
        public int Bodies492DecompFail;
        public int Bodies492WalkClean;
        public int Bodies492ScoreboardSkipped;
        // If true, ignore top-level tag=427 records (only decode nested inside 492).
        // Test knob: reveal whether top-level events are duplicates of nested ones.
        public bool SkipTopLevel427 = false;

        internal void Feed(IList<TlvMessage> messages, DateTime frameTime, bool dedupEnabled = true)
        {
            if (messages == null) return;
            for (int i = 0; i < messages.Count; i++)
            {
                var m = messages[i];
                if (m == null) continue;

                // Top-level tag=427: direct damage record.
                if (m.Tag == DamageTag && m.Body != null && m.Body.Length == DamageBodyLength)
                {
                    if (!SkipTopLevel427) EmitDamage(m.Time, m.Body, 0);
                    continue;
                }

                // Container tag=492: LZ4-compressed TLV stream inside.
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
            if (expected > 10 * 1024 * 1024) return;   // sanity: 10MB uncompressed limit

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

            if (decompressed.Length >= ScoreboardMinUncompressedBytes)
            {
                Bodies492ScoreboardSkipped++;
                return;
            }

            // TLV walk decompressed bytes. Emit tag=427 records.
            var seg = new TcpSegment { Time = msgTime, ClientToServer = false, Seq = 0, Payload = decompressed };
            var res = TlvSplit.Parse(new List<TcpSegment> { seg });
            if (res.S2cOrphanBytes == 0) Bodies492WalkClean++;
            foreach (var sub in res.Messages)
            {
                if (sub.Tag == DamageTag && sub.Body != null && sub.Body.Length == DamageBodyLength)
                {
                    EmitDamage(msgTime, sub.Body, 0);
                }
            }
        }

        void EmitDamage(double msgTime, byte[] buf, int off)
        {
            uint amount = BitConverter.ToUInt32(buf, off + 0);
            uint attacker = BitConverter.ToUInt32(buf, off + 4);
            uint target = BitConverter.ToUInt32(buf, off + 8);
            byte flag = buf[off + 12];
            if (attacker == 0) return;
            var h = OnDamage;
            if (h != null) h(new DamageEvent
            {
                Amount = amount,
                AttackerId = attacker,
                TargetId = target,
                Flag = flag,
                IsCrit = false,
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
