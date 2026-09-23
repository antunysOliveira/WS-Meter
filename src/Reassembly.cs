// ==================== Reassembly layer ====================
//
// Reads pcapng files and produces per-direction TCP payload streams. Also owns
// RawDump — writing the reassembled streams to disk for the offline replay harness.
// Fase 3 will replace the file-poll driven flow with live SharpPcap capture, but the
// interface (TcpSegment list) stays the same.

using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace WSEngine
{
    class TcpSegment
    {
        public double Time;
        public bool ClientToServer;
        public byte[] Payload;
        public uint Seq;
        public byte Flags;       // TCP header byte 13: FIN=0x01, SYN=0x02, RST=0x04, PSH=0x08, ACK=0x10
    }

    static class PcapngReader
    {
        // Parse pcapng file. Returns TCP segments filtered by serverIp (either src or dst must equal it).
        public static List<TcpSegment> ReadTcp(string path, string serverIp, out string diag)
        {
            var sb = new StringBuilder();
            var segs = new List<TcpSegment>();
            byte[] all;
            try
            {
                // Use FileShare.ReadWrite so we can read while dumpcap is still writing.
                using (var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
                using (var ms = new MemoryStream())
                {
                    fs.CopyTo(ms);
                    all = ms.ToArray();
                }
            }
            catch (Exception ex) { diag = "read error: " + ex.Message; return segs; }

            int pos = 0;
            double tsResol = 1e-9; // pcapng default is often 1e-6 (usec) or 1e-9 (nsec); we detect from IDB
            byte lastIfTsResol = 6; // default 10^-6

            int nEpb = 0, nTcp = 0, nIpv4 = 0;

            while (pos + 12 <= all.Length)
            {
                if (pos + 8 > all.Length) break;
                uint blockType = BitConverter.ToUInt32(all, pos);
                uint blockLen  = BitConverter.ToUInt32(all, pos + 4);
                if (blockLen < 12 || pos + (int)blockLen > all.Length) break;

                if (blockType == 0x00000001u) // Interface Description Block
                {
                    // scan options for if_tsresol (code 9)
                    // body: linktype(2) + reserved(2) + snaplen(4) + options
                    int bodyStart = pos + 8;
                    int optsStart = bodyStart + 8;
                    int optsEnd = pos + (int)blockLen - 4;
                    int op = optsStart;
                    while (op + 4 <= optsEnd)
                    {
                        ushort code = BitConverter.ToUInt16(all, op);
                        ushort optLen = BitConverter.ToUInt16(all, op + 2);
                        int valStart = op + 4;
                        if (code == 0) break;
                        if (code == 9 && optLen >= 1)
                        {
                            lastIfTsResol = all[valStart];
                        }
                        int pad = (4 - (optLen % 4)) % 4;
                        op = valStart + optLen + pad;
                    }
                    if ((lastIfTsResol & 0x80) == 0)
                    {
                        // power of 10
                        double exp = lastIfTsResol == 0 ? 0 : lastIfTsResol;
                        tsResol = Math.Pow(10, -exp);
                    }
                    else
                    {
                        int e = lastIfTsResol & 0x7F;
                        tsResol = Math.Pow(2, -e);
                    }
                }
                else if (blockType == 0x00000006u) // Enhanced Packet Block
                {
                    nEpb++;
                    // interface_id(4) + ts_hi(4) + ts_lo(4) + capLen(4) + origLen(4) then packet_data
                    uint tsHi  = BitConverter.ToUInt32(all, pos + 12);
                    uint tsLo  = BitConverter.ToUInt32(all, pos + 16);
                    uint capLn = BitConverter.ToUInt32(all, pos + 20);
                    int dataStart = pos + 28;
                    if (capLn >= 14 && dataStart + capLn <= pos + blockLen)
                    {
                        // Ethernet: dst(6) + src(6) + etherType(2)
                        ushort etherType = (ushort)((all[dataStart + 12] << 8) | all[dataStart + 13]);
                        if (etherType == 0x0800 && capLn >= 34) // IPv4
                        {
                            nIpv4++;
                            int ipStart = dataStart + 14;
                            byte ihl = (byte)(all[ipStart] & 0x0F);
                            int ipHdrLen = ihl * 4;
                            int ipTotalLen = (all[ipStart + 2] << 8) | all[ipStart + 3];
                            byte proto = all[ipStart + 9];
                            string srcIp = string.Format("{0}.{1}.{2}.{3}", all[ipStart + 12], all[ipStart + 13], all[ipStart + 14], all[ipStart + 15]);
                            string dstIp = string.Format("{0}.{1}.{2}.{3}", all[ipStart + 16], all[ipStart + 17], all[ipStart + 18], all[ipStart + 19]);

                            if (proto == 6 && ihl >= 5)
                            {
                                int tcpStart = ipStart + ipHdrLen;
                                if (tcpStart + 20 <= dataStart + capLn)
                                {
                                    byte tcpOff = (byte)((all[tcpStart + 12] >> 4) & 0x0F);
                                    int tcpHdrLen = tcpOff * 4;
                                    int payloadLen = ipTotalLen - ipHdrLen - tcpHdrLen;
                                    uint seq = (uint)((all[tcpStart + 4] << 24) | (all[tcpStart + 5] << 16) | (all[tcpStart + 6] << 8) | all[tcpStart + 7]);
                                    byte flags = all[tcpStart + 13];
                                    bool srcIsServer = srcIp == serverIp;
                                    bool dstIsServer = dstIp == serverIp;
                                    if (srcIsServer || dstIsServer)
                                    {
                                        // Emit if the segment carries payload OR it is a SYN — SYN packets have no
                                        // payload but Fase 0.5 needs them to answer "does this pcap contain the
                                        // handshake?" (Plano armadilha 1: streams that start mid-message.)
                                        bool hasSyn = (flags & 0x02) != 0;
                                        if (payloadLen > 0)
                                        {
                                            int payloadStart = tcpStart + tcpHdrLen;
                                            if (payloadStart + payloadLen <= dataStart + capLn)
                                            {
                                                nTcp++;
                                                byte[] payload = new byte[payloadLen];
                                                Array.Copy(all, payloadStart, payload, 0, payloadLen);
                                                ulong ts = ((ulong)tsHi << 32) | tsLo;
                                                double timeSec = ts * tsResol;
                                                segs.Add(new TcpSegment
                                                {
                                                    Time = timeSec,
                                                    ClientToServer = !srcIsServer,
                                                    Payload = payload,
                                                    Seq = seq,
                                                    Flags = flags
                                                });
                                            }
                                        }
                                        else if (hasSyn)
                                        {
                                            ulong ts = ((ulong)tsHi << 32) | tsLo;
                                            double timeSec = ts * tsResol;
                                            segs.Add(new TcpSegment
                                            {
                                                Time = timeSec,
                                                ClientToServer = !srcIsServer,
                                                Payload = new byte[0],
                                                Seq = seq,
                                                Flags = flags
                                            });
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                pos += (int)blockLen;
            }
            sb.AppendFormat("EPB={0}, IPv4={1}, TCP-with-payload-matching-server={2}, tsResol=1e-{3}", nEpb, nIpv4, nTcp, Math.Log10(1.0 / tsResol));
            diag = sb.ToString();
            return segs;
        }
    }

    // Writes the reassembled s2c/c2s byte streams to disk so the parser can be exercised
    // offline via --replay, with the game closed. Concatenates per-direction payloads in
    // the same observed order that GameFramer.ParseDirection consumes them — same input,
    // deterministic output. Fase 3 will replace this with a proper reassembly stage.
    static class RawDump
    {
        public static string Dump(string dumpsDir, string pcapPath, IEnumerable<TcpSegment> segs)
        {
            Directory.CreateDirectory(dumpsDir);
            string baseName = Path.GetFileNameWithoutExtension(pcapPath);
            string stamp = DateTime.Now.ToString("yyyy-MM-dd_HHmm");
            string label = stamp + "_" + baseName;
            string s2cPath  = Path.Combine(dumpsDir, label + ".s2c.bin");
            string c2sPath  = Path.Combine(dumpsDir, label + ".c2s.bin");
            string notesPath = Path.Combine(dumpsDir, label + ".notes.txt");

            using (var fs = File.Create(s2cPath))
                foreach (var seg in segs)
                    if (!seg.ClientToServer) fs.Write(seg.Payload, 0, seg.Payload.Length);
            using (var fc = File.Create(c2sPath))
                foreach (var seg in segs)
                    if (seg.ClientToServer) fc.Write(seg.Payload, 0, seg.Payload.Length);
            if (!File.Exists(notesPath)) File.WriteAllText(notesPath, "");
            return label;
        }
    }
}
