// ==================== Fase 0: Replay harness ====================
//
// Feeds a .s2c.bin (already-reassembled server→client stream) into the framing layer
// without opening the game or the network. Prints a deterministic summary: byte count,
// message count, top tags, and a SHA-256 digest over (varint-tag-bytes, body-bytes)
// pairs. Two runs on the same .bin MUST produce identical output — that is the Fase 0
// acceptance criterion.
//
// Framing: post-Fase 2, this uses TlvSplit (varint tag + varint len + body). The old
// byte-scan framer (Framing.cs) is deprecated; --replay's digest changed vs the pre-TLV
// baseline (intentional — framing itself changed). See docs/PROTOCOL-NOTES.md.

using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace WSEngine
{
    static class Replay
    {
        public static int DumpFromPcap(string pcapPath)
        {
            if (!File.Exists(pcapPath))
            {
                Console.Error.WriteLine("dump: pcap not found: " + pcapPath);
                return 2;
            }
            string diag;
            var segs = PcapngReader.ReadTcp(pcapPath, "152.233.19.169", out diag);
            if (segs.Count == 0)
            {
                Console.Error.WriteLine("dump: no matching TCP payload — " + diag);
                return 3;
            }
            string root = AppDomain.CurrentDomain.BaseDirectory.TrimEnd('\\');
            string dumpsDir = Path.Combine(root, "dumps");
            string label = RawDump.Dump(dumpsDir, pcapPath, segs);
            Console.Out.WriteLine("wrote: dumps/" + label + ".s2c.bin");
            Console.Out.WriteLine("wrote: dumps/" + label + ".c2s.bin");
            Console.Out.WriteLine("wrote: dumps/" + label + ".notes.txt (empty — fill by hand)");
            Console.Out.WriteLine("diag:  " + diag);
            return 0;
        }

        public static int Run(string s2cPath)
        {
            if (!File.Exists(s2cPath))
            {
                WriteBoth(s2cPath, "replay: file not found: " + s2cPath);
                return 2;
            }
            byte[] bytes = File.ReadAllBytes(s2cPath);
            var fakeSeg = new TcpSegment
            {
                Time = 0.0,
                ClientToServer = false,
                Seq = 0,
                Payload = bytes
            };
            var segs = new List<TcpSegment> { fakeSeg };
            var result = TlvSplit.Parse(segs);

            var histogram = new Dictionary<int, int>();
            string digestHex;
            using (var sha = System.Security.Cryptography.SHA256.Create())
            {
                foreach (var m in result.Messages)
                {
                    if (!histogram.ContainsKey(m.Tag)) histogram[m.Tag] = 0;
                    histogram[m.Tag]++;
                    // Digest over: tag encoded as varint bytes (raw framing bytes)
                    // + body bytes. Two runs on the same input hash identical.
                    var tagBytes = EncodeVarint(m.Tag);
                    sha.TransformBlock(tagBytes, 0, tagBytes.Length, null, 0);
                    if (m.Body != null && m.Body.Length > 0)
                        sha.TransformBlock(m.Body, 0, m.Body.Length, null, 0);
                }
                sha.TransformFinalBlock(new byte[0], 0, 0);
                var hb = new StringBuilder();
                foreach (var b in sha.Hash) hb.Append(b.ToString("x2"));
                digestHex = hb.ToString();
            }

            var top = new List<KeyValuePair<int, int>>(histogram);
            top.Sort((a, b) => b.Value.CompareTo(a.Value));

            var report = new StringBuilder();
            report.AppendLine("file:     " + s2cPath);
            report.AppendLine("bytes:    " + bytes.Length);
            report.AppendLine("walked:   " + result.S2cBytesWalked + " (" + (100.0 * result.S2cBytesWalked / Math.Max(1, bytes.Length)).ToString("F2") + "%)");
            report.AppendLine("orphans:  " + result.S2cOrphanBytes);
            report.AppendLine("stop:     " + result.StopReasonS2c);
            report.AppendLine("messages: " + result.Messages.Count);
            report.AppendLine("digest:   " + digestHex);
            report.AppendLine("top tags (count | tag_dec | tag_hex):");
            for (int i = 0; i < top.Count && i < 20; i++)
                report.AppendLine(string.Format("  {0,8}  {1,5}   0x{2:x}", top[i].Value, top[i].Key, top[i].Key));
            WriteBoth(s2cPath, report.ToString().TrimEnd());
            return 0;
        }

        // --replay-assert: sum tag=427 damage via TlvDamageDecoder and compare to expected total.
        // Exit 0 if within tolerance, 5 if outside. Used by tools/_test-damage-decoder.ps1 for
        // regression coverage after Fase 7 rewrite.
        public static int Assert(string s2cPath, long expectedTotal, double tolerancePct)
        {
            if (!File.Exists(s2cPath))
            {
                WriteBoth(s2cPath, "replay-assert: file not found: " + s2cPath);
                return 2;
            }
            byte[] bytes = File.ReadAllBytes(s2cPath);
            var fakeSeg = new TcpSegment
            {
                Time = 0.0,
                ClientToServer = false,
                Seq = 0,
                Payload = bytes
            };
            var result = TlvSplit.Parse(new List<TcpSegment> { fakeSeg });

            var decoder = new TlvDamageDecoderV3();
            long total = 0;
            int events = 0;
            int zeroAtt = 0;
            decoder.OnDamage += e =>
            {
                total += e.Amount;
                events++;
                if (e.AttackerId == 0) zeroAtt++;
            };
            decoder.Feed(result.Messages, DateTime.UtcNow, false);

            double diffPct = expectedTotal == 0 ? 0.0 : Math.Abs(total - expectedTotal) * 100.0 / expectedTotal;
            bool pass = diffPct <= tolerancePct;
            var line = string.Format(System.Globalization.CultureInfo.InvariantCulture,
                "replay-assert {0}: total={1} expected={2} diff={3:F2}% tolerance={4:F2}% events={5} zeroAtt={6} {7}",
                s2cPath, total, expectedTotal, diffPct, tolerancePct, events, zeroAtt, pass ? "PASS" : "FAIL");
            WriteBoth(s2cPath, line);
            return pass ? 0 : 5;
        }

        static byte[] EncodeVarint(int v)
        {
            var list = new List<byte>();
            uint u = (uint)v;
            while (true)
            {
                byte b = (byte)(u & 0x7F);
                u >>= 7;
                if (u == 0) { list.Add(b); break; }
                list.Add((byte)(b | 0x80));
            }
            return list.ToArray();
        }

        // Writes to console (when a parent console is attached) AND to a sidecar file
        // <bin>.replay.txt — the sidecar guarantees determinism-check output survives
        // even when the admin-manifest UAC re-launch severs stdio.
        static void WriteBoth(string s2cPath, string text)
        {
            try { Console.Out.WriteLine(text); } catch { }
            try { File.WriteAllText(s2cPath + ".replay.txt", text); } catch { }
        }
    }
}
