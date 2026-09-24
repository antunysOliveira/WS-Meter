// ==================== tag=26 (1a 29) — Entity spawn ====================
//
// [MEDIDO 2026-09-24] via correlation of tag=26 bodies with mob-types.json
// nos raids "Horror da Masmorra" (tid=15623) e "Demônio das Areias Douradas"
// (tid=16363). Ambos raids retornaram max_hp=1.499.488 nos bytes 14-17
// (idêntico → provável cap de raid), enquanto mobs comuns (Lobo Escuridão,
// Esqueleto, etc) retornaram valores <10k.
//
// Body layout (41 bytes) — tag=26 len=41 body começa após "1a 29":
//   [0..1]   u16 LE  type_id (chave em mob-types.json)
//   [2..5]   u32 LE  entity_id (high byte 0x05 / 0xF6 = mob range)
//   [6..9]   float LE (0.5f / 0.6f observado — scale/velocity?)
//   [10..11] u8 u8   x, y
//   [12..13] u8 u8   x_old, y_old
//   [14..17] u32 LE  max_hp        ← CAMPO NOVO usado pra rank
//   [18..19] u16 LE  const 0x0004
//   [20..40] payload restante (varia por tipo)
//
// Rank derivado de max_hp:
//   > 800.000  → raid   (bosses de instância raid)
//   > 100.000  → chefe  (bosses normais + adds de raid tipo Fragmento)
//   > 10.000   → forte  (elites/mini-bosses de zona)
//   ≤ 10.000   → comum  (mobs padrão)
//
// Nota: legacy layout doc (CLAUDE.md antigo) descrevia bytes 2-3 como
// "counter" e 4-7 como "summon_id". Isso era pra pets de player (tag=26
// também usado). Empiricamente pra mob spawns o layout acima está correto.

using System;
using System.Collections.Generic;

namespace WSEngine
{
    public class EntitySpawnInfo
    {
        public uint EntityId;
        public int TypeId;
        public int MaxHp;
        public string Rank;   // "raid" | "chefe" | "forte" | "comum" | null
        public double CapturedAtSec;
    }

    public static class Tag26EntitySpawnDecoder
    {
        const int Tag = 26;
        const int BodyLen = 41;

        // HP thresholds — ver spec no cabeçalho.
        public const int HpRaid  = 800000;
        public const int HpChefe = 100000;
        public const int HpForte = 10000;

        // Rank helper — pode ser chamado externamente (ex: damage decoder que
        // já sabe target's max_hp via cache).
        public static string RankFromHp(int hp)
        {
            if (hp <= 0) return null;
            if (hp > HpRaid)  return "raid";
            if (hp > HpChefe) return "chefe";
            if (hp > HpForte) return "forte";
            return "comum";
        }

        // Constrói mapa entity_id → EntitySpawnInfo a partir de messages TLV.
        // Também segue dentro de tag=492 (bulk envelope lz4).
        internal static Dictionary<uint, EntitySpawnInfo> Build(
            IList<TlvMessage> messages, double captureStartTime)
        {
            var map = new Dictionary<uint, EntitySpawnInfo>();
            if (messages == null) return map;

            for (int i = 0; i < messages.Count; i++)
            {
                var m = messages[i];
                if (m == null || m.Body == null) continue;

                if (m.Tag == Tag && m.Body.Length == BodyLen)
                {
                    Handle(m.Body, m.Time - captureStartTime, map);
                    continue;
                }

                if (m.Tag == 492 && m.Body.Length >= 5)
                {
                    byte[] dec = TryDecompress492(m.Body);
                    if (dec == null) continue;
                    var seg = new TcpSegment { Time = m.Time, ClientToServer = false, Seq = 0, Payload = dec };
                    var inner = TlvSplit.Parse(new List<TcpSegment> { seg });
                    foreach (var im in inner.Messages)
                    {
                        if (im == null || im.Body == null) continue;
                        if (im.Tag == Tag && im.Body.Length == BodyLen)
                            Handle(im.Body, m.Time - captureStartTime, map);
                    }
                }
            }
            return map;
        }

        static void Handle(byte[] body, double t, Dictionary<uint, EntitySpawnInfo> map)
        {
            int typeId = BitConverter.ToUInt16(body, 0);
            uint entityId = BitConverter.ToUInt32(body, 2);
            int maxHp = BitConverter.ToInt32(body, 14);

            if (entityId == 0 || typeId == 0) return;
            // Sane HP range — descarta values absurdos (NPC/entity com layout
            // diferente ocasionalmente casa no scan bruto).
            if (maxHp <= 0 || maxHp > 100000000) return;

            // Só considera entities com high byte no range de mob conhecido
            // (0x05, 0x07, 0x09, 0x0C, 0x10, 0x57, 0xF6). Isso filtra NPCs
            // e strings coincidentes.
            byte hi = (byte)((entityId >> 24) & 0xFF);
            if (hi != 0x05 && hi != 0x07 && hi != 0x09 && hi != 0x0C
                && hi != 0x10 && hi != 0x57 && hi != 0xF6) return;

            var info = new EntitySpawnInfo
            {
                EntityId = entityId,
                TypeId = typeId,
                MaxHp = maxHp,
                Rank = RankFromHp(maxHp),
                CapturedAtSec = t,
            };
            // Último wins — se spawn re-emitido, atualiza (mob pode reset em respawn)
            map[entityId] = info;
        }

        static byte[] TryDecompress492(byte[] body)
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
