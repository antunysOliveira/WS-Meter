// ws-datamine.exe — Game data file parser for Warspear Online pak-out/
// Usage: ws-datamine.exe --in <pak-out-dir> --out <data-dir>
//
// Parses (as of 2026-09-20):
//   Names/strings:  classes.csd, monsters.dat, client_ui_strings_pt.dat
//   Combat:         guild_skills.csd, skills.csd (class combat skills), bonuses.dat (buff/passive names)
//   World:          zones.csd, sectors.csd
//   Progression:    talents.csd
//   (all name resolution via strings_pt.dat)
//
// File layout confirmed empirically by hexdump analysis:
//   strings_pt.dat:            [id:u32 LE][UTF-16 LE null-terminated string] * N
//   client_ui_strings_pt.dat:  same format, 2707 entries (UI-only strings)
//   classes.csd:               20 records * 30 bytes; magic 2a 1c, class_id u32 @+2, faction u32 @+6, name_id u16 @+10
//   monsters.dat:              12-byte header (ver u32 + count u32 + unk u32) + records * 20 bytes;
//                              each record: [flags:u16][faction:u16][unk1:u32][type_id:u16][level:u16][name_key:u32]
//   guild_skills.csd:          24 records * 134 bytes; magic 02 83 01, skill_id u16 @+3, name_key u32 @+5
//   bonuses.dat:               115 records * 16 bytes; [bonus_id:u16][flags:u16][name_key:u32][desc_key:u32][pad:u32]
//   skills.csd:                variable records; magic 08 b7 02 marks each skill record head;
//                              [magic 3B][skill_id:u32][name_key:u32][desc_key:u32]... (322 named class-skill records)
//   zones.csd:                 variable records; magic 2d 2f (with 2d 0b variants); [magic 2B][zone_id:u32][name_key:u32]...
//   sectors.csd:               14 records * 10 bytes; magic 26 08, sector_id u32 @+2, name_key u32 @+6
//   talents.csd:               ~1175 records * 34 bytes; magic 23 20, talent_id u32 @+2, name_key u32 @+10
//   weapons.csd:               variable records; magic 30 3e, item_id u32 @+2, name_key u32 @+12 (3632 named)
//   armors.csd:                variable records; magic 31 40, item_id u32 @+2, name_key u32 @+12 (6505 named)
//   consumables.csd:           variable records; magic 38 3f, item_id u32 @+2, name_key u32 @+12 (998 named)

using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace Datamine
{
    class Datamine
    {
        static int Main(string[] args)
        {
            try
            {
                string pakDir = null, outDir = null;
                for (int i = 0; i < args.Length; i++)
                {
                    if (args[i] == "--in"  && i + 1 < args.Length) pakDir = args[++i];
                    if (args[i] == "--out" && i + 1 < args.Length) outDir = args[++i];
                }
                if (pakDir == null || outDir == null)
                {
                    Console.Error.WriteLine("Usage: ws-datamine.exe --in <pak-out-dir> --out <data-dir>");
                    return 1;
                }
                pakDir = Path.GetFullPath(pakDir);
                outDir = Path.GetFullPath(outDir);
                if (!Directory.Exists(pakDir))  { Console.Error.WriteLine("ERROR: pak-out dir not found: " + pakDir); return 1; }
                if (!Directory.Exists(outDir))  { Directory.CreateDirectory(outDir); }

                Console.WriteLine("[datamine] Loading strings_pt.dat ...");
                var strings = LoadStrings(Path.Combine(pakDir, "strings_pt.dat"));
                Console.WriteLine("  " + strings.Count + " entries");

                Console.WriteLine("[datamine] Loading client_ui_strings_pt.dat ...");
                var uiStrings = LoadStrings(Path.Combine(pakDir, "client_ui_strings_pt.dat"));
                Console.WriteLine("  " + uiStrings.Count + " entries");

                Console.WriteLine("[datamine] Parsing classes.csd ...");
                var classes = ParseClasses(Path.Combine(pakDir, "classes.csd"), strings);
                Console.WriteLine("  " + classes.Count + " entries");
                WriteJson(Path.Combine(outDir, "class-names.json"), classes);

                Console.WriteLine("[datamine] Parsing monsters.dat ...");
                var mobs = ParseMonsters(Path.Combine(pakDir, "monsters.dat"), strings);
                Console.WriteLine("  " + mobs.Count + " entries");
                WriteJsonWithLevel(Path.Combine(outDir, "mob-types.json"), mobs);

                Console.WriteLine("[datamine] Writing ui-strings-pt.json ...");
                WriteJson(Path.Combine(outDir, "ui-strings-pt.json"), uiStrings);

                Console.WriteLine("[datamine] Parsing guild_skills.csd ...");
                var skills = ParseGuildSkills(Path.Combine(pakDir, "guild_skills.csd"), strings);
                Console.WriteLine("  " + skills.Count + " entries");
                WriteJson(Path.Combine(outDir, "skill-names.json"), skills);

                Console.WriteLine("[datamine] Parsing bonuses.dat ...");
                var bonuses = ParseBonuses(Path.Combine(pakDir, "bonuses.dat"), strings);
                Console.WriteLine("  " + bonuses.Count + " entries");
                WriteJson(Path.Combine(outDir, "bonus-names.json"), bonuses);

                Console.WriteLine("[datamine] Parsing skills.csd (class combat skills) ...");
                var classSkills = ParseClassSkills(Path.Combine(pakDir, "skills.csd"), strings);
                Console.WriteLine("  " + classSkills.Count + " entries");
                WriteJson(Path.Combine(outDir, "class-skill-names.json"), classSkills);

                Console.WriteLine("[datamine] Parsing zones.csd ...");
                var zones = ParseZones(Path.Combine(pakDir, "zones.csd"), strings);
                Console.WriteLine("  " + zones.Count + " entries");
                WriteJson(Path.Combine(outDir, "zone-names.json"), zones);

                Console.WriteLine("[datamine] Parsing sectors.csd ...");
                var sectors = ParseSectors(Path.Combine(pakDir, "sectors.csd"), strings);
                Console.WriteLine("  " + sectors.Count + " entries");
                WriteJson(Path.Combine(outDir, "sector-names.json"), sectors);

                Console.WriteLine("[datamine] Parsing talents.csd ...");
                var talents = ParseTalents(Path.Combine(pakDir, "talents.csd"), strings);
                Console.WriteLine("  " + talents.Count + " entries");
                WriteJson(Path.Combine(outDir, "talent-names.json"), talents);

                Console.WriteLine("[datamine] Parsing weapons.csd ...");
                var weapons = ParseItemFile(Path.Combine(pakDir, "weapons.csd"), 0x30, 0x3e, strings);
                Console.WriteLine("  " + weapons.Count + " entries");
                WriteJson(Path.Combine(outDir, "weapon-names.json"), weapons);

                Console.WriteLine("[datamine] Parsing armors.csd ...");
                var armors = ParseItemFile(Path.Combine(pakDir, "armors.csd"), 0x31, 0x40, strings);
                Console.WriteLine("  " + armors.Count + " entries");
                WriteJson(Path.Combine(outDir, "armor-names.json"), armors);

                Console.WriteLine("[datamine] Parsing consumables.csd ...");
                var consumables = ParseItemFile(Path.Combine(pakDir, "consumables.csd"), 0x38, 0x3f, strings);
                Console.WriteLine("  " + consumables.Count + " entries");
                WriteJson(Path.Combine(outDir, "consumable-names.json"), consumables);

                // Category map: byte @+6 of each consumable record is the item-type
                // enum (cross-referenced with item_types.csd):
                //   0x0b = comida | 0x0c = pergaminho | 0x0d = poção
                // Emit item_id → category for the tag=429 buff UI.
                Console.WriteLine("[datamine] Extracting consumable categories ...");
                var cats = ParseConsumableCategories(Path.Combine(pakDir, "consumables.csd"));
                Console.WriteLine("  " + cats.Count + " categorized");
                WriteJson(Path.Combine(outDir, "consumable-categories.json"), cats);

                // Additional item files — all share the +12 name_key layout
                ParseAndWriteItem(pakDir, outDir, strings, "quest_items.csd",              0x33, 0x24, "quest-item-names.json");
                ParseAndWriteItem(pakDir, outDir, strings, "guts_items.csd",               0x36, 0x20, "guts-item-names.json");
                ParseAndWriteItem(pakDir, outDir, strings, "outfit_items.csd",             0x3b, 0x36, "outfit-item-names.json");
                ParseAndWriteItem(pakDir, outDir, strings, "envelope_items.csd",           0x42, 0x24, "envelope-item-names.json");
                ParseAndWriteItem(pakDir, outDir, strings, "simple_service_items.csd",     0x3d, 0x20, "service-item-names.json");
                ParseAndWriteItem(pakDir, outDir, strings, "smiles_packs.csd",             0x48, 0x24, "smile-pack-names.json");
                ParseAndWriteItem(pakDir, outDir, strings, "skill_book_items.csd",         0x44, 0x28, "skill-book-names.json");
                ParseAndWriteItem(pakDir, outDir, strings, "dummy_items.csd",              0x2e, 0x20, "dummy-item-names.json");
                ParseAndWriteItem(pakDir, outDir, strings, "skill_amplifier_items.csd",    0x37, 0x20, "skill-amplifier-names.json");
                ParseAndWriteItem(pakDir, outDir, strings, "crystal_items.csd",            0x3a, 0x28, "crystal-item-names.json");
                ParseAndWriteItem(pakDir, outDir, strings, "haircut_pack_items.csd",       0x47, 0x24, "haircut-pack-names.json");
                ParseAndWriteItem(pakDir, outDir, strings, "rune_items.csd",               0x39, 0x28, "rune-item-names.json");
                ParseAndWriteItem(pakDir, outDir, strings, "craft_items.csd",              0x34, 0x20, "craft-item-names.json");
                ParseAndWriteItem(pakDir, outDir, strings, "resource_items.csd",           0x35, 0x20, "resource-item-names.json");
                ParseAndWriteItem(pakDir, outDir, strings, "spawn_object_items.csd",       0x5b, 0x63, "spawn-object-names.json");
                ParseAndWriteItem(pakDir, outDir, strings, "amplifier_items.csd",          0x41, 0x22, "amplifier-item-names.json");
                ParseAndWriteItem(pakDir, outDir, strings, "item_packs.csd",               0x3f, 0x5e, "item-pack-names.json");
                ParseAndWriteItem(pakDir, outDir, strings, "expansion_items.csd",          0x40, 0x22, "expansion-item-names.json");
                ParseAndWriteItem(pakDir, outDir, strings, "simple_service_chestkey_items.csd", 0x3e, 0x24, "chestkey-item-names.json");

                Console.WriteLine("[datamine] Parsing territories.csd ...");
                var territories = ParseCustom(Path.Combine(pakDir, "territories.csd"), 0x25, 0x13, 2, 6, strings);
                Console.WriteLine("  " + territories.Count + " entries");
                WriteJson(Path.Combine(outDir, "territory-names.json"), territories);

                Console.WriteLine("[datamine] Parsing achievements.csd ...");
                var achievements = ParseCustom(Path.Combine(pakDir, "achievements.csd"), 0x14, 0x1f, 2, 14, strings);
                Console.WriteLine("  " + achievements.Count + " entries");
                WriteJson(Path.Combine(outDir, "achievement-names.json"), achievements);

                ParseCustomAndWrite(pakDir, outDir, strings, "defined_influences.csd",       0x18, 0x12, 2, 10, "influence-names.json");
                ParseCustomAndWrite(pakDir, outDir, strings, "craft_job_info.csd",           0x0d, 0x31, 2,  6, "craft-job-names.json");
                ParseCustomAndWrite(pakDir, outDir, strings, "factions.csd",                 0x06, 0x14, 4,  8, "faction-names.json");
                ParseCustomAndWrite(pakDir, outDir, strings, "summon_skills.csd",            0x54, 0x68, 2, 10, "summon-skill-names.json");
                ParseCustomAndWrite(pakDir, outDir, strings, "castle_buildings.csd",         0x1e, 0x0c, 2,  6, "castle-building-names.json");
                ParseCustomAndWrite(pakDir, outDir, strings, "catacombs_reward_categories.csd", 0x61, 0x10, 2, 10, "catacomb-reward-names.json");
                ParseCustomAndWrite(pakDir, outDir, strings, "currencies.csd",               0x2c, 0x10, 6, 10, "currency-names.json");
                ParseCustomAndWrite(pakDir, outDir, strings, "talents_milestones.csd",       0x56, 0x10, 2,  6, "talent-milestone-names.json");
                ParseCustomAndWrite(pakDir, outDir, strings, "castles.csd",                  0x1b, 0x16, 2,  6, "castle-names.json");
                ParseCustomAndWrite(pakDir, outDir, strings, "castle_building_types.csd",    0x1d, 0x14, 2,  6, "castle-building-type-names.json");

                ParseCustomAndWrite(pakDir, outDir, strings, "jewelry.csd",                 0x32, 0x3a, 2, 12, "jewelry-names.json");
                ParseCustomAndWrite(pakDir, outDir, strings, "iaobjects.csd",               0x28, 0x1d, 2,  8, "iaobject-names.json");
                ParseCustomAndWrite(pakDir, outDir, strings, "npc_dolls.csd",               0x62, 0x33, 2,  6, "npc-doll-names.json");
                ParseCustomAndWrite(pakDir, outDir, strings, "item_sets.csd",               0x3c, 0x10, 2, 10, "item-set-names.json");
                ParseCustomAndWrite(pakDir, outDir, strings, "hints.csd",                   0x2b, 0x0f, 2,  6, "hint-names.json");
                ParseCustomAndWrite(pakDir, outDir, strings, "achievements_goal.csd",       0x16, 0x13, 2, 12, "achievement-goal-names.json");
                ParseCustomAndWrite(pakDir, outDir, strings, "achievements_group.csd",      0x15, 0x11, 2,  6, "achievement-group-names.json");
                ParseCustomAndWrite(pakDir, outDir, strings, "title_guild_achievements.csd",0x4c, 0x12, 2,  6, "title-guild-achievement-names.json");
                ParseCustomAndWrite(pakDir, outDir, strings, "castle_building_levels.csd",  0x1f, 0x37, 2, 10, "castle-building-level-names.json");

                Console.WriteLine("[datamine] Parsing quests/pt/ ...");
                var quests = ParseQuests(Path.Combine(pakDir, "quests", "pt"));
                Console.WriteLine("  " + quests.Count + " entries");
                WriteJson(Path.Combine(outDir, "quest-names.json"), quests);

                Console.WriteLine("[datamine] Done. Files written to: " + outDir);
                return 0;
            }
            catch (System.IO.FileNotFoundException e)
            {
                Console.Error.WriteLine("ERROR: file not found: " + e.FileName);
                Console.Error.WriteLine("Hint: run pakextract --extract-all first to populate pak-out/");
                return 3;
            }
            catch (System.IO.IOException e)
            {
                Console.Error.WriteLine("ERROR: I/O failure: " + e.Message);
                return 3;
            }
            catch (System.Exception e)
            {
                Console.Error.WriteLine("ERROR: " + e.GetType().Name + ": " + e.Message);
                return 4;
            }
        }

        // ─── Parsers ────────────────────────────────────────────────────────────

        static Dictionary<string, string> ParseClasses(string path, Dictionary<int, string> strings)
        {
            // 20 records × 30 bytes. No file header.
            // Each record: [magic:u16=0x1c2a][class_id:u32][faction:u32][name_id:u16][...]
            const int RECORD_SIZE = 30;
            byte[] b = File.ReadAllBytes(path);
            int count = b.Length / RECORD_SIZE;
            var result = new Dictionary<string, string>();
            for (int i = 0; i < count; i++)
            {
                int off = i * RECORD_SIZE;
                uint classId = BitConverter.ToUInt32(b, off + 2);
                int  nameId  = BitConverter.ToUInt16(b, off + 10);
                string name  = "";
                if (strings.ContainsKey(nameId)) name = strings[nameId];
                if (name == "") name = "class_" + classId;
                result[classId.ToString()] = name;
            }
            return result;
        }

        // Mob entry: name + level (level=0 means unknown/not set)
        struct MobEntry { public string Name; public int Level; }

        static Dictionary<string, MobEntry> ParseMonsters(string path, Dictionary<int, string> strings)
        {
            // Header: [version:u32=1][count:u32=6846][unk:u32=39] — 12 bytes
            // Records: 20 bytes each (total records = (filesize-12)/20 ≈ 20930)
            // Each record: [flags:u16][faction:u16][unk1:u32][type_id:u16][level:u16][name_key:u32]
            const int HEADER = 12;
            const int REC    = 20;
            byte[] b = File.ReadAllBytes(path);
            int count = (b.Length - HEADER) / REC;
            var result = new Dictionary<string, MobEntry>();
            for (int i = 0; i < count; i++)
            {
                int off = HEADER + i * REC;
                int typeId   = BitConverter.ToUInt16(b, off + 8);
                int level    = BitConverter.ToUInt16(b, off + 10);
                int nameKey  = BitConverter.ToInt32(b,  off + 12);
                if (typeId == 0) continue;
                string name = "";
                if (strings.ContainsKey(nameKey) && strings[nameKey].Length > 0)
                    name = strings[nameKey];
                if (name == "") continue;  // skip unnamed/internal entries
                string key = typeId.ToString();
                // Keep first encounter (records with same typeId appear in duplicate envelopes)
                if (!result.ContainsKey(key))
                    result[key] = new MobEntry { Name = name, Level = level };
            }
            return result;
        }

        static Dictionary<string, string> ParseGuildSkills(string path, Dictionary<int, string> strings)
        {
            // 24 records × 134 bytes.
            // Each record: [magic:3 bytes=02 83 01][skill_id:u16][name_key:u32][...]
            const int RECORD_SIZE = 134;
            byte[] b = File.ReadAllBytes(path);
            int count = b.Length / RECORD_SIZE;
            var result = new Dictionary<string, string>();
            for (int i = 0; i < count; i++)
            {
                int off = i * RECORD_SIZE;
                int skillId = BitConverter.ToUInt16(b, off + 3);
                int nameKey = BitConverter.ToInt32(b,  off + 5);
                string name = "";
                if (strings.ContainsKey(nameKey) && strings[nameKey].Length > 0)
                    name = strings[nameKey];
                if (name == "") continue;
                result[skillId.ToString()] = name;
            }
            return result;
        }

        static Dictionary<string, string> ParseBonuses(string path, Dictionary<int, string> strings)
        {
            // 115 records * 16 bytes.
            // Each: [bonus_id:u16][flags:u16][name_key:u32][desc_key:u32][pad:u32]
            const int REC = 16;
            byte[] b = File.ReadAllBytes(path);
            int count = b.Length / REC;
            var result = new Dictionary<string, string>();
            for (int i = 0; i < count; i++)
            {
                int off = i * REC;
                int bid = BitConverter.ToUInt16(b, off);
                int nk  = BitConverter.ToInt32 (b, off + 4);
                string name = "";
                if (strings.ContainsKey(nk) && strings[nk].Length > 0) name = strings[nk];
                if (name == "" || name == "-") continue;
                result[bid.ToString()] = name;
            }
            return result;
        }

        static Dictionary<string, string> ParseClassSkills(string path, Dictionary<int, string> strings)
        {
            // Variable-length records. Each starts with magic [08 b7 02] followed by
            // [skill_id:u32][name_key:u32][desc_key:u32]. Records may contain nested
            // level-detail sub-records — walker just scans for the magic marker.
            byte[] b = File.ReadAllBytes(path);
            var result = new Dictionary<string, string>();
            int i = 0;
            while (i < b.Length - 15)
            {
                if (b[i] == 0x08 && b[i+1] == 0xb7 && b[i+2] == 0x02)
                {
                    uint sid = BitConverter.ToUInt32(b, i + 3);
                    int  nk  = BitConverter.ToInt32 (b, i + 7);
                    if (sid >= 1 && sid < 100000 && strings.ContainsKey(nk))
                    {
                        string name = strings[nk];
                        if (name.Length > 0 && name != "-" && !result.ContainsKey(sid.ToString()))
                            result[sid.ToString()] = name;
                    }
                }
                i++;
            }
            return result;
        }

        static Dictionary<string, string> ParseZones(string path, Dictionary<int, string> strings)
        {
            // Variable-length records. Head magic [2d 2f] (regions) or [2d 0b] (sub-zones).
            // After magic: [zone_id:u32][name_key:u32]. Records include variable trailer.
            byte[] b = File.ReadAllBytes(path);
            var result = new Dictionary<string, string>();
            int i = 0;
            while (i < b.Length - 10)
            {
                bool isMagic = (b[i] == 0x2d && (b[i+1] == 0x2f || b[i+1] == 0x0b));
                if (isMagic)
                {
                    uint zid = BitConverter.ToUInt32(b, i + 2);
                    int  nk  = BitConverter.ToInt32 (b, i + 6);
                    if (zid > 0 && zid < 10000 && strings.ContainsKey(nk))
                    {
                        string name = strings[nk];
                        if (name.Length > 0 && name != "-" && !result.ContainsKey(zid.ToString()))
                            result[zid.ToString()] = name;
                    }
                }
                i++;
            }
            return result;
        }

        static Dictionary<string, string> ParseSectors(string path, Dictionary<int, string> strings)
        {
            // 14 records * 10 bytes. [magic 26 08][sector_id:u32][name_key:u32]
            const int REC = 10;
            byte[] b = File.ReadAllBytes(path);
            int count = b.Length / REC;
            var result = new Dictionary<string, string>();
            for (int i = 0; i < count; i++)
            {
                int off = i * REC;
                uint sid = BitConverter.ToUInt32(b, off + 2);
                int  nk  = BitConverter.ToInt32 (b, off + 6);
                if (strings.ContainsKey(nk))
                {
                    string name = strings[nk];
                    if (name.Length > 0) result[sid.ToString()] = name;
                }
            }
            return result;
        }

        // Parse quest INI files (UTF-16 LE) — one per quest_id in quests/pt/.
        // Extracts name= from [quest] section, keyed by id= (or filename).
        static Dictionary<string, string> ParseQuests(string questDir)
        {
            var result = new Dictionary<string, string>();
            if (!Directory.Exists(questDir)) return result;
            foreach (string path in Directory.GetFiles(questDir))
            {
                string text;
                try
                {
                    byte[] raw = File.ReadAllBytes(path);
                    if (raw.Length < 4) continue;
                    text = Encoding.Unicode.GetString(raw);
                    if (text.Length > 0 && text[0] == '﻿') text = text.Substring(1);
                }
                catch { continue; }

                string name = null, qid = null;
                bool inQuest = false;
                foreach (string rawLine in text.Split('\n'))
                {
                    string line = rawLine.TrimEnd('\r').Trim();
                    if (line.Length == 0) continue;
                    if (line[0] == '[')
                    {
                        inQuest = string.Equals(line, "[quest]", StringComparison.OrdinalIgnoreCase);
                        if (!inQuest && name != null && qid != null) break;
                        continue;
                    }
                    if (!inQuest) continue;
                    int eq = line.IndexOf('=');
                    if (eq <= 0) continue;
                    string k = line.Substring(0, eq).Trim();
                    string v = line.Substring(eq + 1).Trim();
                    if (string.Equals(k, "name", StringComparison.OrdinalIgnoreCase)) name = v;
                    else if (string.Equals(k, "id",   StringComparison.OrdinalIgnoreCase)) qid = v;
                }

                if (qid == null) qid = Path.GetFileName(path);
                if (name != null && name.Length > 0 && !result.ContainsKey(qid))
                    result[qid] = name;
            }
            return result;
        }

        static void ParseCustomAndWrite(string pakDir, string outDir, Dictionary<int, string> strings, string csdName, byte m0, byte m1, int idOff, int nkOff, string jsonName)
        {
            string path = Path.Combine(pakDir, csdName);
            if (!File.Exists(path)) { Console.WriteLine("  [skip] " + csdName + " not found"); return; }
            Console.WriteLine("[datamine] Parsing " + csdName + " ...");
            var d = ParseCustom(path, m0, m1, idOff, nkOff, strings);
            Console.WriteLine("  " + d.Count + " entries");
            WriteJson(Path.Combine(outDir, jsonName), d);
        }

        // Custom parser: magic + id_offset + name_key_offset (both from record start).
        static Dictionary<string, string> ParseCustom(string path, byte m0, byte m1, int idOff, int nkOff, Dictionary<int, string> strings)
        {
            byte[] b = File.ReadAllBytes(path);
            var result = new Dictionary<string, string>();
            int i = 0;
            while (i < b.Length - nkOff - 4)
            {
                if (b[i] == m0 && b[i+1] == m1)
                {
                    uint iid = BitConverter.ToUInt32(b, i + idOff);
                    int  nk  = BitConverter.ToInt32 (b, i + nkOff);
                    if (iid > 0 && iid < 500000 && strings.ContainsKey(nk))
                    {
                        string name = strings[nk];
                        if (name.Length > 2 && name != "-" && !result.ContainsKey(iid.ToString()))
                            result[iid.ToString()] = name;
                    }
                }
                i++;
            }
            return result;
        }

        static void ParseAndWriteItem(string pakDir, string outDir, Dictionary<int, string> strings, string csdName, byte m0, byte m1, string jsonName)
        {
            string path = Path.Combine(pakDir, csdName);
            if (!File.Exists(path)) { Console.WriteLine("  [skip] " + csdName + " not found"); return; }
            Console.WriteLine("[datamine] Parsing " + csdName + " ...");
            var d = ParseItemFile(path, m0, m1, strings);
            Console.WriteLine("  " + d.Count + " entries");
            WriteJson(Path.Combine(outDir, jsonName), d);
        }

        // Generic item parser: variable-length records, each starting with a 2-byte magic.
        // Layout: [magic:2 bytes][item_id:u32][flags:u16][sub_id:u32][name_key:u32]...
        // Used for weapons.csd, armors.csd, consumables.csd.
        static Dictionary<string, string> ParseItemFile(string path, byte magic0, byte magic1, Dictionary<int, string> strings)
        {
            byte[] b = File.ReadAllBytes(path);
            var result = new Dictionary<string, string>();
            int i = 0;
            while (i < b.Length - 16)
            {
                if (b[i] == magic0 && b[i+1] == magic1)
                {
                    uint iid = BitConverter.ToUInt32(b, i + 2);
                    int  nk  = BitConverter.ToInt32 (b, i + 12);
                    if (iid > 0 && iid < 500000 && strings.ContainsKey(nk))
                    {
                        string name = strings[nk];
                        if (name.Length > 0 && name != "-" && !result.ContainsKey(iid.ToString()))
                            result[iid.ToString()] = name;
                    }
                }
                i++;
            }
            return result;
        }

        // Consumable category extractor. Uses the same magic-scan as ParseItemFile,
        // but reads the type byte @+6 instead of the name key.
        static Dictionary<string, string> ParseConsumableCategories(string path)
        {
            byte[] b = File.ReadAllBytes(path);
            var result = new Dictionary<string, string>();
            int i = 0;
            while (i < b.Length - 20)
            {
                if (b[i] == 0x38 && b[i + 1] == 0x3f)
                {
                    uint iid = BitConverter.ToUInt32(b, i + 2);
                    byte cat = b[i + 6];
                    if (iid > 0 && iid < 500000)
                    {
                        string name = null;
                        if (cat == 0x0b) name = "comida";
                        else if (cat == 0x0c) name = "pergaminho";
                        else if (cat == 0x0d) name = "poção";
                        if (name != null && !result.ContainsKey(iid.ToString()))
                            result[iid.ToString()] = name;
                    }
                }
                i++;
            }
            return result;
        }

        static Dictionary<string, string> ParseTalents(string path, Dictionary<int, string> strings)
        {
            // ~1175 records. Magic [23 20] every 34 bytes. [magic 2B][talent_id:u32][???][name_key:u32 @+10]
            const int REC = 34;
            byte[] b = File.ReadAllBytes(path);
            int count = b.Length / REC;
            var result = new Dictionary<string, string>();
            for (int i = 0; i < count; i++)
            {
                int off = i * REC;
                if (off + REC > b.Length) break;
                if (b[off] != 0x23 || b[off+1] != 0x20) continue;   // guard against drift
                uint tid = BitConverter.ToUInt32(b, off + 2);
                int  nk  = BitConverter.ToInt32 (b, off + 10);
                if (strings.ContainsKey(nk))
                {
                    string name = strings[nk];
                    if (name.Length > 0 && name != "-") result[tid.ToString()] = name;
                }
            }
            return result;
        }

        // ─── String table loader ─────────────────────────────────────────────────
        // Format: [id:u32 LE][UTF-16 LE null-terminated string] * N
        static Dictionary<int, string> LoadStrings(string path)
        {
            byte[] b = File.ReadAllBytes(path);
            var d = new Dictionary<int, string>();
            int pos = 0;
            while (pos + 4 <= b.Length)
            {
                int id = BitConverter.ToInt32(b, pos); pos += 4;
                int strStart = pos;
                bool foundTerminator = false;
                while (pos + 2 <= b.Length)
                {
                    ushort ch = BitConverter.ToUInt16(b, pos);
                    if (ch == 0) { foundTerminator = true; pos += 2; break; }
                    pos += 2;
                }
                if (!foundTerminator) break;  // corrupt tail — skip rather than inject garbage
                int strByteLen = pos - strStart - 2;
                string s = Encoding.Unicode.GetString(b, strStart, strByteLen);
                d[id] = s;
            }
            return d;
        }

        // ─── JSON writers ────────────────────────────────────────────────────────
        static void WriteJson(string path, Dictionary<string, string> map)
        {
            using (var w = new StreamWriter(path, false, new UTF8Encoding(false)))
            {
                w.WriteLine("{");
                int idx = 0;
                foreach (var kv in map)
                {
                    bool last = (++idx == map.Count);
                    w.WriteLine("  " + JsonStr(kv.Key) + ": " + JsonStr(kv.Value) + (last ? "" : ","));
                }
                w.WriteLine("}");
            }
        }

        static void WriteJson(string path, Dictionary<int, string> map)
        {
            var strMap = new Dictionary<string, string>();
            foreach (var kv in map)
                strMap[kv.Key.ToString()] = kv.Value;
            WriteJson(path, strMap);
        }

        // CONTRACT: emit flat objects only. GameData.LoadMobTypes regex assumes no nested {}.
        // If a new field is added, keep it primitive OR update GameData in lockstep.
        static void WriteJsonWithLevel(string path, Dictionary<string, MobEntry> mobs)
        {
            using (var w = new StreamWriter(path, false, new UTF8Encoding(false)))
            {
                w.WriteLine("{");
                int idx = 0;
                foreach (var kv in mobs)
                {
                    bool last = (++idx == mobs.Count);
                    string comma = last ? "" : ",";
                    if (kv.Value.Level > 0)
                        w.WriteLine("  " + JsonStr(kv.Key) + ": {\"name\": " + JsonStr(kv.Value.Name) + ", \"level\": " + kv.Value.Level + "}" + comma);
                    else
                        w.WriteLine("  " + JsonStr(kv.Key) + ": {\"name\": " + JsonStr(kv.Value.Name) + "}" + comma);
                }
                w.WriteLine("}");
            }
        }

        static string JsonStr(string s)
        {
            var sb = new StringBuilder("\"");
            foreach (char c in s)
            {
                if      (c == '"')  sb.Append("\\\"");
                else if (c == '\\') sb.Append("\\\\");
                else if (c == '\n') sb.Append("\\n");
                else if (c == '\r') sb.Append("\\r");
                else if (c == '\t') sb.Append("\\t");
                else if (c < 0x20) { sb.Append("\\u"); sb.Append(((int)c).ToString("x4")); }
                else sb.Append(c);
            }
            sb.Append('"');
            return sb.ToString();
        }
    }
}
