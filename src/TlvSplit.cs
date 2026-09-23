// ==================== Framing (real): varint-TLV splitter ====================
//
// Warspear's real framing, confirmed in Fase 2:
//
//   [tag: LEB128 varint] [len: LEB128 varint] [body: len bytes]
//
// - tag is the opcode (no separate opcode byte; the tag IS the opcode)
// - len is the body size (does NOT include the tag/len header)
// - both tag and len are variable-length LEB128 ints (7 bits + continuation)
//
// Containers: some tags (492 = `ec 03` bytes, others TBD) carry a sub-TLV stream in
// their body. This flat splitter does NOT recurse — recursion is a Fase 5 concern
// once specific containers are named. Consumers can call TlvSplit.Parse on Body if
// they know a given tag is a container.
//
// Fase 2 acceptance: TlvSplit walks every .s2c.bin in the archive to EOF with zero
// orphan bytes. Ran by --tlv-scan.

using System;
using System.Collections.Generic;

namespace WSEngine
{
    class TlvMessage
    {
        public int Index;                // 0-based position in parse output (post-sort by time)
        public double Time;              // segment timestamp of the first byte of the tag
        public bool ClientToServer;      // direction
        public int Tag;                  // decoded LEB128 tag
        public int Length;               // decoded LEB128 length (body size in bytes)
        public byte[] Body;              // len bytes of body, exact copy
        public int TagLen;               // number of bytes consumed by the tag varint (1..5)
        public int LenLen;               // number of bytes consumed by the len varint (1..5)
        public int StreamPos;            // byte offset in the reassembled per-direction stream
    }

    static class TlvSplit
    {
        // Result of a Parse call.
        public class Result
        {
            public List<TlvMessage> Messages = new List<TlvMessage>();
            public int S2cBytesTotal;
            public int S2cBytesWalked;
            public int S2cOrphanBytes;
            public int C2sBytesTotal;
            public int C2sBytesWalked;
            public int C2sOrphanBytes;
            public string StopReasonS2c = "eof clean";
            public string StopReasonC2s = "eof clean";
        }

        public static Result Parse(List<TcpSegment> segs)
        {
            var r = new Result();
            ParseDirection(segs, false, r);
            ParseDirection(segs, true,  r);
            r.Messages.Sort((a, b) => a.Time.CompareTo(b.Time));
            for (int i = 0; i < r.Messages.Count; i++) r.Messages[i].Index = i;
            return r;
        }

        static void ParseDirection(List<TcpSegment> segs, bool c2s, Result r)
        {
            // Reassemble the per-direction byte stream in observed order (matches the old
            // GameFramer contract; Fase 3 will swap this for real seq-based reassembly).
            int total = 0;
            foreach (var s in segs)
                if (s.ClientToServer == c2s && s.Payload != null) total += s.Payload.Length;

            var buf = new byte[total];
            var timeByByte = new double[total];
            int off = 0;
            foreach (var s in segs)
            {
                if (s.ClientToServer != c2s || s.Payload == null) continue;
                Array.Copy(s.Payload, 0, buf, off, s.Payload.Length);
                for (int i = 0; i < s.Payload.Length; i++) timeByByte[off + i] = s.Time;
                off += s.Payload.Length;
            }
            if (c2s) r.C2sBytesTotal = total; else r.S2cBytesTotal = total;

            int pos = 0;
            string stopReason = "eof clean";
            while (pos < total)
            {
                int tagStart = pos;
                int tagLen;
                int tag = ReadVarint(buf, pos, out tagLen);
                if (tagLen == 0) { stopReason = "bad tag @0x" + pos.ToString("x"); break; }
                pos += tagLen;
                int lenLen;
                int msgLen = ReadVarint(buf, pos, out lenLen);
                if (lenLen == 0) { stopReason = "bad len @0x" + pos.ToString("x"); break; }
                pos += lenLen;
                if (msgLen < 0 || msgLen > 65535) { stopReason = "len out of range (" + msgLen + ")"; break; }
                if (pos + msgLen > total) { stopReason = "eof (partial " + (total - tagStart) + " B)"; break; }

                var body = new byte[msgLen];
                if (msgLen > 0) Array.Copy(buf, pos, body, 0, msgLen);
                r.Messages.Add(new TlvMessage
                {
                    Time = timeByByte[tagStart],
                    ClientToServer = c2s,
                    Tag = tag,
                    Length = msgLen,
                    Body = body,
                    TagLen = tagLen,
                    LenLen = lenLen,
                    StreamPos = tagStart
                });
                pos += msgLen;
            }
            if (c2s)
            {
                r.C2sBytesWalked = pos;
                r.C2sOrphanBytes = total - pos;
                r.StopReasonC2s = stopReason;
            }
            else
            {
                r.S2cBytesWalked = pos;
                r.S2cOrphanBytes = total - pos;
                r.StopReasonS2c = stopReason;
            }
        }

        // LEB128 varint decoder. Returns the decoded int and sets `consumed` to the number
        // of bytes read (0 if malformed / would overflow 32-bit).
        public static int ReadVarint(byte[] data, int pos, out int consumed)
        {
            int result = 0, shift = 0;
            for (int i = 0; i < 5; i++)
            {
                if (pos + i >= data.Length) { consumed = 0; return -1; }
                byte b = data[pos + i];
                result |= (b & 0x7F) << shift;
                if ((b & 0x80) == 0) { consumed = i + 1; return result; }
                shift += 7;
                if (shift > 28) break;
            }
            consumed = 0; return -1;
        }
    }
}
