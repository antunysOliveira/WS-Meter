// Tag9NameDecoder.cs
//
// Roster/list entries do servidor emitem tag=9 com body compacto
// `[nlen u8][name ASCII * nlen][entity_id u32 LE]`. Mora principalmente
// nested dentro de tag=492 LZ4; ocasionalmente top-level.
//
// [MEDIDO 2026-09-25] via probe _probe-tag9-layout.ps1 nas 4 capturas
// de referência:
//   ws_20260921_183825: 21 nicks
//   ws_20260923_234032: 16 nicks
//   ws_20260924_171950:  3 nicks
//   nomes.pcapng      : 39 nicks (all real players do amigo)
//
// Diferencia-se do tag=65 (chat sender) por:
//   - Sem header 3B, name_len direto em byte 0.
//   - Não tem 2nd-id/2nd-field (chat tinha idAfter mystery).
//   - Body length exata = 1 + nlen + 4.
//
// Origin precedence: tag207 > tag551 > tag554 > tag9 > tag65. Ver
// MainForm.OriginPriority.

using System;
using System.Collections.Generic;
using System.Text;

namespace WSEngine
{
    static class Tag9NameDecoder
    {
        const int Tag = 9;
        const int MinNameLen = 3;
        const int MaxNameLen = 20;

        // Extrai nick+id de todo tag=9 (top-level + nested em tag=492 LZ4).
        // Grava em `names` — chamador aplica precedência via CommitName.
        public static void Extract(IList<TlvMessage> msgs, Dictionary<uint, string> names)
        {
            if (msgs == null || names == null) return;
            foreach (var m in msgs)
            {
                if (m == null || m.Body == null || m.ClientToServer) continue;
                if (m.Tag == Tag) TryParseBody(m.Body, names);
                if (m.Tag == 492 && m.Body.Length >= 5)
                {
                    int pos = 0; int N;
                    if (!ReadVarint(m.Body, ref pos, out N)) continue;
                    if (N < 0 || pos + N + 4 != m.Body.Length) continue;
                    uint expected = BitConverter.ToUInt32(m.Body, pos + N);
                    if (expected > 10 * 1024 * 1024) continue;
                    byte[] dec;
                    try { dec = Lz4.DecompressBlock(m.Body, pos, N, (int)expected); } catch { continue; }
                    var seg = new TcpSegment { Time = m.Time, ClientToServer = false, Seq = 0, Payload = dec };
                    var res = TlvSplit.Parse(new List<TcpSegment> { seg });
                    foreach (var sub in res.Messages)
                        if (sub != null && sub.Tag == Tag && sub.Body != null) TryParseBody(sub.Body, names);
                }
            }
        }

        static void TryParseBody(byte[] body, Dictionary<uint, string> names)
        {
            if (body == null || body.Length < 1 + MinNameLen + 4) return;
            byte nlen = body[0];
            if (nlen < MinNameLen || nlen > MaxNameLen) return;
            if (1 + nlen + 4 != body.Length) return;   // strict — evita false positives
            byte first = body[1];
            if (!((first >= 'A' && first <= 'Z') || (first >= 'a' && first <= 'z'))) return;
            int alpha = 0;
            for (int k = 0; k < nlen; k++)
            {
                byte b = body[1 + k];
                if (b < 0x20 || b > 0x7E) return;
                if ((b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z')) alpha++;
            }
            if (alpha < Math.Max(3, nlen - 3)) return;
            uint id = BitConverter.ToUInt32(body, 1 + nlen);
            if ((id >> 24) != 0 || id < 0x00010000) return;
            names[id] = Encoding.ASCII.GetString(body, 1, nlen);
        }

        static bool ReadVarint(byte[] b, ref int pos, out int val)
        {
            val = 0; int shift = 0;
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
