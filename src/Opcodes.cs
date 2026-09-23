// ==================== Opcodes layer ====================
//
// Extract semantic content from framed GameFrame lists: printable strings, entity
// sightings via opcode 0x13, etc. The heavier parsers (damage, summon owner, names)
// still live inside MainForm and will move here as Fase 4/5 tighten the contract.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace WSEngine
{
    class ExtractedString
    {
        public string Text;
        public string Kind; // "ascii" | "utf16le"
        public int FirstFrame;
        public int Count;
    }

    class EntitySighting
    {
        public uint Id;
        public int Count;
        public byte LastX, LastY;
    }

    static class Extractor
    {
        public static List<ExtractedString> Strings(List<TlvMessage> messages, int minLen = 3)
        {
            var map = new Dictionary<string, ExtractedString>();

            for (int i = 0; i < messages.Count; i++)
            {
                var f = messages[i];
                var body = f.Body;
                // ASCII runs
                int run = 0;
                for (int j = 0; j <= body.Length; j++)
                {
                    bool printable = j < body.Length && body[j] >= 0x20 && body[j] < 0x7F;
                    if (printable) run++;
                    else
                    {
                        if (run >= minLen)
                        {
                            string s = Encoding.ASCII.GetString(body, j - run, run);
                            Add(map, s, "ascii", i);
                        }
                        run = 0;
                    }
                }
                // UTF-16 LE runs: consecutive (printable, 0x00) pairs
                run = 0;
                for (int j = 0; j + 1 <= body.Length; j += 2)
                {
                    if (j + 1 >= body.Length) break;
                    byte lo = body[j], hi = body[j + 1];
                    bool printable = hi == 0 && lo >= 0x20 && lo < 0x7F;
                    // allow common Latin-1 supplements too (accented chars 0xA1..0xFF with hi=0)
                    if (!printable && hi == 0 && lo >= 0xA0) printable = true;
                    if (printable) run++;
                    else
                    {
                        if (run >= minLen)
                        {
                            int startByte = j - (run * 2);
                            string s = Encoding.Unicode.GetString(body, startByte, run * 2);
                            Add(map, s, "utf16le", i);
                        }
                        run = 0;
                    }
                }
                if (run >= minLen)
                {
                    int startByte = body.Length - (run * 2);
                    if (startByte >= 0)
                    {
                        string s = Encoding.Unicode.GetString(body, startByte, run * 2);
                        Add(map, s, "utf16le", i);
                    }
                }
            }
            var list = map.Values.ToList();
            list.Sort((a, b) => b.Count.CompareTo(a.Count));
            return list;
        }

        static void Add(Dictionary<string, ExtractedString> map, string s, string kind, int idx)
        {
            s = s.Trim();
            if (s.Length < 3) return;
            string key = kind + "|" + s;
            ExtractedString e;
            if (!map.TryGetValue(key, out e))
            {
                e = new ExtractedString { Text = s, Kind = kind, FirstFrame = idx, Count = 0 };
                map[key] = e;
            }
            e.Count++;
        }

        // Entity IDs from tag=19 (0x13 varint, position update): body = 9 bytes
        //   [x:u8][y:u8][entity_id:u32 LE][?][old_x:u8][old_y:u8]  (best-effort guess,
        //   confirmed against memscan `0x13` type marker in the entity struct — Fase 5
        //   will nail down the exact field layout).
        public static List<EntitySighting> Entities(List<TlvMessage> messages)
        {
            var map = new Dictionary<uint, EntitySighting>();
            foreach (var m in messages)
            {
                if (m.Tag != 19 || m.Length < 6 || m.Body == null) continue;
                uint id = BitConverter.ToUInt32(m.Body, 2);
                EntitySighting e;
                if (!map.TryGetValue(id, out e))
                {
                    e = new EntitySighting { Id = id, Count = 0 };
                    map[id] = e;
                }
                e.Count++;
                e.LastX = m.Body[0];
                e.LastY = m.Body[1];
            }
            var list = map.Values.ToList();
            list.Sort((a, b) => b.Count.CompareTo(a.Count));
            return list;
        }
    }
}
