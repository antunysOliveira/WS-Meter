// GameData.cs — runtime lookup module for Warspear game data.
// Loads JSON files from the data/ directory on first Init call.
// Pure hand-rolled JSON parsing — no NuGet, no System.Web, no JSON.NET.
// Compiled with csc.exe v4.0.30319 (.NET Framework 4).

using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;

public enum EntityKind { Unknown, Player, Mob, Npc, Pet }

public static class GameData
{
    // -----------------------------------------------------------------------
    // Internal state
    // -----------------------------------------------------------------------

    static readonly Dictionary<uint,   string> _mobs         = new Dictionary<uint,   string>();
    static readonly Dictionary<int,    string> _classes      = new Dictionary<int,    string>();
    static readonly Dictionary<int,    string> _skills       = new Dictionary<int,    string>();
    static readonly Dictionary<int,    string> _uiStrings    = new Dictionary<int,    string>();
    static readonly Dictionary<int,    string> _bonuses      = new Dictionary<int,    string>();
    static readonly Dictionary<int,    string> _classSkills  = new Dictionary<int,    string>();
    static readonly Dictionary<int,    string> _zones        = new Dictionary<int,    string>();
    static readonly Dictionary<int,    string> _sectors      = new Dictionary<int,    string>();
    static readonly Dictionary<int,    string> _talents      = new Dictionary<int,    string>();
    static readonly Dictionary<int,    string> _weapons      = new Dictionary<int,    string>();
    static readonly Dictionary<int,    string> _armors       = new Dictionary<int,    string>();
    static readonly Dictionary<int,    string> _consumables  = new Dictionary<int,    string>();
    // item_id → category ("poção" / "pergaminho" / "comida"). Sourced from
    // consumables.csd byte @+6 cross-referenced with item_types.csd:
    //   0x0b = comida | 0x0c = pergaminho | 0x0d = poção
    static readonly Dictionary<int,    string> _consumableCat = new Dictionary<int,    string>();
    // Combined items lookup — merged from all *_items.csd files (name only, no category)
    static readonly Dictionary<int,    string> _items        = new Dictionary<int,    string>();
    static readonly Dictionary<int,    string> _territories  = new Dictionary<int,    string>();
    static readonly Dictionary<int,    string> _achievements = new Dictionary<int,    string>();
    static readonly Dictionary<int,    string> _influences   = new Dictionary<int,    string>();
    static readonly Dictionary<int,    string> _factions     = new Dictionary<int,    string>();
    static readonly Dictionary<int,    string> _quests       = new Dictionary<int,    string>();
    static volatile bool _loaded = false;
    static readonly object _lock  = new object();

    // -----------------------------------------------------------------------
    // Public counts
    // -----------------------------------------------------------------------

    public static int MobCount        { get { return _mobs.Count;        } }
    public static int ClassCount      { get { return _classes.Count;     } }
    public static int SkillCount      { get { return _skills.Count;      } }
    public static int UiStringCount   { get { return _uiStrings.Count;   } }
    public static int BonusCount      { get { return _bonuses.Count;     } }
    public static int ClassSkillCount { get { return _classSkills.Count; } }
    public static int ZoneCount       { get { return _zones.Count;       } }
    public static int SectorCount     { get { return _sectors.Count;     } }
    public static int TalentCount     { get { return _talents.Count;     } }
    public static int WeaponCount     { get { return _weapons.Count;     } }
    public static int ArmorCount      { get { return _armors.Count;      } }
    public static int ConsumableCount { get { return _consumables.Count; } }
    public static int ItemCount       { get { return _items.Count;       } }
    public static int TerritoryCount  { get { return _territories.Count; } }
    public static int AchievementCount{ get { return _achievements.Count;} }
    public static int InfluenceCount  { get { return _influences.Count;  } }
    public static int FactionCount    { get { return _factions.Count;    } }
    public static int QuestCount      { get { return _quests.Count;      } }

    // -----------------------------------------------------------------------
    // Init — idempotent; loads on first call only
    // -----------------------------------------------------------------------

    public static void Init(string dataDir)
    {
        if (_loaded) return;
        lock (_lock)
        {
            if (_loaded) return;

            LoadFlatStringMap(Path.Combine(dataDir, "class-names.json"),
                (s, v) => { int id; if (int.TryParse(s, out id)) _classes[id] = v; });

            LoadFlatStringMap(Path.Combine(dataDir, "skill-names.json"),
                (s, v) => { int id; if (int.TryParse(s, out id)) _skills[id] = v; });

            LoadFlatStringMap(Path.Combine(dataDir, "ui-strings-pt.json"),
                (s, v) => { int id; if (int.TryParse(s, out id)) _uiStrings[id] = v; });

            LoadMobTypes(Path.Combine(dataDir, "mob-types.json"));

            LoadFlatStringMap(Path.Combine(dataDir, "bonus-names.json"),
                (s, v) => { int id; if (int.TryParse(s, out id)) _bonuses[id] = v; });

            LoadFlatStringMap(Path.Combine(dataDir, "class-skill-names.json"),
                (s, v) => { int id; if (int.TryParse(s, out id)) _classSkills[id] = v; });

            LoadFlatStringMap(Path.Combine(dataDir, "zone-names.json"),
                (s, v) => { int id; if (int.TryParse(s, out id)) _zones[id] = v; });

            LoadFlatStringMap(Path.Combine(dataDir, "sector-names.json"),
                (s, v) => { int id; if (int.TryParse(s, out id)) _sectors[id] = v; });

            LoadFlatStringMap(Path.Combine(dataDir, "talent-names.json"),
                (s, v) => { int id; if (int.TryParse(s, out id)) _talents[id] = v; });

            LoadFlatStringMap(Path.Combine(dataDir, "weapon-names.json"),
                (s, v) => { int id; if (int.TryParse(s, out id)) _weapons[id] = v; });

            LoadFlatStringMap(Path.Combine(dataDir, "armor-names.json"),
                (s, v) => { int id; if (int.TryParse(s, out id)) _armors[id] = v; });

            LoadFlatStringMap(Path.Combine(dataDir, "consumable-names.json"),
                (s, v) => { int id; if (int.TryParse(s, out id)) _consumables[id] = v; });

            LoadFlatStringMap(Path.Combine(dataDir, "consumable-categories.json"),
                (s, v) => { int id; if (int.TryParse(s, out id)) _consumableCat[id] = v; });

            // Load all *-item-names.json + weapon/armor/consumable into unified _items lookup
            // for global item name resolution regardless of category.
            string[] itemJsons = {
                "weapon-names.json", "armor-names.json", "consumable-names.json",
                "quest-item-names.json", "guts-item-names.json", "outfit-item-names.json",
                "envelope-item-names.json", "service-item-names.json", "smile-pack-names.json",
                "skill-book-names.json", "dummy-item-names.json", "skill-amplifier-names.json",
                "crystal-item-names.json", "haircut-pack-names.json", "rune-item-names.json",
                "craft-item-names.json", "resource-item-names.json", "spawn-object-names.json",
                "amplifier-item-names.json", "item-pack-names.json", "expansion-item-names.json",
                "chestkey-item-names.json"
            };
            foreach (var jn in itemJsons)
            {
                LoadFlatStringMap(Path.Combine(dataDir, jn),
                    (s, v) => { int id; if (int.TryParse(s, out id) && !_items.ContainsKey(id)) _items[id] = v; });
            }

            LoadFlatStringMap(Path.Combine(dataDir, "territory-names.json"),
                (s, v) => { int id; if (int.TryParse(s, out id)) _territories[id] = v; });

            LoadFlatStringMap(Path.Combine(dataDir, "achievement-names.json"),
                (s, v) => { int id; if (int.TryParse(s, out id)) _achievements[id] = v; });

            LoadFlatStringMap(Path.Combine(dataDir, "influence-names.json"),
                (s, v) => { int id; if (int.TryParse(s, out id)) _influences[id] = v; });

            LoadFlatStringMap(Path.Combine(dataDir, "faction-names.json"),
                (s, v) => { int id; if (int.TryParse(s, out id)) _factions[id] = v; });

            LoadFlatStringMap(Path.Combine(dataDir, "quest-names.json"),
                (s, v) => { int id; if (int.TryParse(s, out id)) _quests[id] = v; });

            if (_mobs.Count == 0 && _classes.Count == 0 && _skills.Count == 0 && _uiStrings.Count == 0)
            {
                System.Console.Error.WriteLine("[GameData] WARNING: no data files loaded from " + dataDir + " — MobName/ClassName/etc will always return null");
            }
            _loaded = true;
        }
    }

    // -----------------------------------------------------------------------
    // Public lookups
    // -----------------------------------------------------------------------

    public static string MobName(uint typeId)
    {
        string v;
        return _mobs.TryGetValue(typeId, out v) ? v : null;
    }

    public static string ClassName(int classId)
    {
        string v;
        return _classes.TryGetValue(classId, out v) ? v : null;
    }

    public static string SkillName(int skillId)
    {
        string v;
        return _skills.TryGetValue(skillId, out v) ? v : null;
    }

    public static string UiString(int key)
    {
        string v;
        return _uiStrings.TryGetValue(key, out v) ? v : null;
    }

    public static string BonusName(int id)      { string v; return _bonuses    .TryGetValue(id, out v) ? v : null; }
    public static string ClassSkillName(int id) { string v; return _classSkills.TryGetValue(id, out v) ? v : null; }
    public static string ZoneName(int id)       { string v; return _zones      .TryGetValue(id, out v) ? v : null; }
    public static string SectorName(int id)     { string v; return _sectors    .TryGetValue(id, out v) ? v : null; }
    public static string TalentName(int id)     { string v; return _talents    .TryGetValue(id, out v) ? v : null; }
    public static string WeaponName(int id)     { string v; return _weapons    .TryGetValue(id, out v) ? v : null; }
    public static string ArmorName(int id)      { string v; return _armors     .TryGetValue(id, out v) ? v : null; }
    public static string ConsumableName(int id) { string v; return _consumables.TryGetValue(id, out v) ? v : null; }
    public static string ConsumableCategory(int id) { string v; return _consumableCat.TryGetValue(id, out v) ? v : null; }
    public static string ItemName(int id)       { string v; return _items      .TryGetValue(id, out v) ? v : null; }
    public static string TerritoryName(int id)  { string v; return _territories.TryGetValue(id, out v) ? v : null; }
    public static string AchievementName(int id){ string v; return _achievements.TryGetValue(id, out v) ? v : null; }
    public static string InfluenceName(int id)  { string v; return _influences  .TryGetValue(id, out v) ? v : null; }
    public static string FactionName(int id)    { string v; return _factions    .TryGetValue(id, out v) ? v : null; }
    public static string QuestName(int id)      { string v; return _quests      .TryGetValue(id, out v) ? v : null; }

    public static EntityKind Classify(uint entityId, uint? typeId)
    {
        if (typeId.HasValue && _mobs.ContainsKey(typeId.Value))
            return EntityKind.Mob;

        byte high = (byte)(entityId >> 24);
        if (high == 0x00) return EntityKind.Player;
        if (high == 0x03 || high == 0x04 || high == 0x05 || high == 0x07 ||
            high == 0x09 || high == 0x0C || high == 0x10 || high == 0x57)
            return EntityKind.Mob;

        return EntityKind.Unknown;
    }

    // -----------------------------------------------------------------------
    // JSON parsers — hand-rolled, regex-based, no NuGet
    // -----------------------------------------------------------------------

    // Loads a flat {"K": "V"} JSON map.
    // onPair is called for each key-value pair with unescaped values.
    static void LoadFlatStringMap(string path,
        Action<string, string> onPair)
    {
        if (!File.Exists(path)) return;
        string json = File.ReadAllText(path, Encoding.UTF8);

        // Match "key": "value" — handles escaped chars inside strings
        Regex re = new Regex(
            "\"((?:[^\"\\\\]|\\\\.)*)\"\\s*:\\s*\"((?:[^\"\\\\]|\\\\.)*)\""
        );

        foreach (Match m in re.Matches(json))
        {
            string key = JsonUnescape(m.Groups[1].Value);
            string val = JsonUnescape(m.Groups[2].Value);
            onPair(key, val);
        }
    }

    // Loads mob-types.json: {"<id>": {"name": "V", "level": N?}, ...}
    // We only need the name (and the id as the dict key).
    static void LoadMobTypes(string path)
    {
        if (!File.Exists(path)) return;
        string json = File.ReadAllText(path, Encoding.UTF8);

        // Match the outer id key followed by the inner object containing "name": "..."
        // Pattern: "<id>": {... "name": "<value>" ...}
        // We use a two-step approach: find each top-level entry, then extract name from it.

        // Step 1: find each "id": { ... } block.
        // We iterate with a regex that matches "digits": { non-brace* }
        // For safety with nested braces (none expected in this file), we do a simple scan.

        // CONTRACT: mob-types.json entries must be flat objects {"name":str, "level":int?}.
        // Nested objects would break the [^}]* regex below. If schema grows, replace with
        // bracket-balanced parser. Corresponding writer: Datamine.WriteJsonWithLevel.
        Regex entryRe = new Regex(
            "\"(\\d+)\"\\s*:\\s*\\{([^}]*)\\}"
        );
        Regex nameRe = new Regex(
            "\"name\"\\s*:\\s*\"((?:[^\"\\\\]|\\\\.)*)\""
        );

        foreach (Match m in entryRe.Matches(json))
        {
            string idStr  = m.Groups[1].Value;
            string body   = m.Groups[2].Value;

            Match nm = nameRe.Match(body);
            if (!nm.Success) continue;

            uint id;
            if (!uint.TryParse(idStr, out id)) continue;

            string name = JsonUnescape(nm.Groups[1].Value);
            _mobs[id] = name;
        }
    }

    // -----------------------------------------------------------------------
    // JSON string unescaping
    // -----------------------------------------------------------------------

    static string JsonUnescape(string s)
    {
        if (s.IndexOf('\\') < 0) return s; // fast path — no escapes

        StringBuilder sb = new StringBuilder(s.Length);
        int i = 0;
        while (i < s.Length)
        {
            char c = s[i];
            if (c == '\\' && i + 1 < s.Length)
            {
                char next = s[i + 1];
                switch (next)
                {
                    case '"':  sb.Append('"');  i += 2; break;
                    case '\\': sb.Append('\\'); i += 2; break;
                    case '/':  sb.Append('/');  i += 2; break;
                    case 'n':  sb.Append('\n'); i += 2; break;
                    case 'r':  sb.Append('\r'); i += 2; break;
                    case 't':  sb.Append('\t'); i += 2; break;
                    case 'b':  sb.Append('\b'); i += 2; break;
                    case 'f':  sb.Append('\f'); i += 2; break;
                    case 'u':
                        if (i + 5 < s.Length)
                        {
                            string hex = s.Substring(i + 2, 4);
                            int codePoint;
                            if (TryParseHex4(hex, out codePoint))
                            {
                                sb.Append((char)codePoint);
                                i += 6;
                                break;
                            }
                        }
                        sb.Append(c);
                        i++;
                        break;
                    default:
                        sb.Append(c);
                        i++;
                        break;
                }
            }
            else
            {
                sb.Append(c);
                i++;
            }
        }
        return sb.ToString();
    }

    static bool TryParseHex4(string s, out int result)
    {
        result = 0;
        if (s.Length != 4) return false;
        for (int i = 0; i < 4; i++)
        {
            char c = s[i];
            int digit;
            if (c >= '0' && c <= '9')      digit = c - '0';
            else if (c >= 'a' && c <= 'f') digit = c - 'a' + 10;
            else if (c >= 'A' && c <= 'F') digit = c - 'A' + 10;
            else return false;
            result = (result << 4) | digit;
        }
        return true;
    }
}
