// SummonOwnerMap.cs
//
// Reads tag=26 (0x1a) entity-spawn bodies and produces:
//   - Owners map:  summon entity_id → owner player entity_id
//   - AllSummonEids set: every entity_id whose type_id is a registered summon
//     (SummonRegistry), regardless of whether the owner field is populated.
//
// [LIDO] static RE (docs/CLIENT-RE-R5.md + spawn26 probes 2026-09-21):
//   tag=26 wire class reader FUN_00664d00 body layout (41 bytes):
//     +0     u16    type_id  (key in mob-types.json / SummonRegistry.ByTid)
//     +2     u32    entity_id
//     +6     u32    float (size/scale)
//     +10..21  12B  vec2 fields + level bytes
//     +22..23  u16  level (0x64=100 typical)
//     +24..34  padding zeros
//     +35     u32   owner entity_id (player-range 0x00xxxxxx) or 0 for wild mobs
//     +39..40 2B    trailing padding
//
// [MEDIDO 2026-09-25 - pós update Warspear v13.4.4]
//   High byte do entity_id mudou de 0x05 para 0x0B em TODOS os spawns
//   (mobs e invocações). Layout do body ficou idêntico.
//   Ver docs/PROTOCOL-NOTES.md seção "2026-09-25 entity_id range shift".
//
// Filtro anterior "(summonId >> 24) != 0x05" foi removido: classificação de
// invocação passou a ser feita SOMENTE pela whitelist SummonRegistry (tid),
// não pelo byte alto do eid. Assim o parser sobrevive à próxima migração de
// namespace que o servidor fizer.

using System;
using System.Collections.Generic;

namespace WSEngine
{
    internal class SummonMapResult
    {
        public Dictionary<uint, uint> Owners = new Dictionary<uint, uint>();
        public HashSet<uint> AllSummonEids = new HashSet<uint>();
        // eid → tid — usado pra rotear damage de invocação sem dono pro bucket
        // correto por classe ("Invocação de Necromante (sem dono)" etc).
        public Dictionary<uint, int> TidByEid = new Dictionary<uint, int>();
        // classId → 1 (marcador de presença). Usado pra logar "classe X
        // presente na área" quando um summon é avistado.
        public HashSet<int> ClassesPresent = new HashSet<int>();
    }

    internal static class SummonOwnerMap
    {
        const int SpawnTag = 26;
        const int MinSpawnBodyLen = 39;   // need bytes 35..38 = owner u32
        const int TypeIdOffset   = 0;
        const int SummonIdOffset = 2;
        const int OwnerIdOffset  = 35;

        // Back-compat wrapper — returns just the owners map. New callers should
        // use BuildResult() to get AllSummonEids for solo-fallback / labeling.
        public static Dictionary<uint, uint> Build(IList<TlvMessage> messages)
        {
            return BuildResult(messages).Owners;
        }

        public static SummonMapResult BuildResult(IList<TlvMessage> messages)
        {
            var r = new SummonMapResult();
            if (messages == null) return r;

            for (int i = 0; i < messages.Count; i++)
            {
                var m = messages[i];
                if (m == null) continue;

                if (m.Tag == SpawnTag && m.Body != null && m.Body.Length >= MinSpawnBodyLen)
                {
                    AddIfSummon(r, m.Body);
                    continue;
                }

                if (m.Tag == 492 && m.Body != null && m.Body.Length >= 5)
                {
                    ScanContainer(m.Body, r);
                }
            }
            return r;
        }

        static void ScanContainer(byte[] body, SummonMapResult r)
        {
            int pos = 0;
            int N;
            if (!ReadVarint(body, ref pos, out N)) return;
            if (N < 0 || pos + N + 4 != body.Length) return;
            uint expected = BitConverter.ToUInt32(body, pos + N);
            if (expected > 10 * 1024 * 1024) return;
            byte[] decompressed;
            try { decompressed = Lz4.DecompressBlock(body, pos, N, (int)expected); }
            catch { return; }

            var seg = new TcpSegment { Time = 0.0, ClientToServer = false, Seq = 0, Payload = decompressed };
            var res = TlvSplit.Parse(new List<TcpSegment> { seg });
            foreach (var sub in res.Messages)
            {
                if (sub.Tag == SpawnTag && sub.Body != null && sub.Body.Length >= MinSpawnBodyLen)
                    AddIfSummon(r, sub.Body);
            }
        }

        static void AddIfSummon(SummonMapResult r, byte[] body)
        {
            int tid = BitConverter.ToUInt16(body, TypeIdOffset);
            SummonInfo info = SummonRegistry.Get(tid);
            if (info == null) return;

            uint summonId = BitConverter.ToUInt32(body, SummonIdOffset);
            if (summonId == 0) return;
            r.AllSummonEids.Add(summonId);
            r.TidByEid[summonId] = tid;
            r.ClassesPresent.Add(info.OwnerClassId);

            uint ownerId = BitConverter.ToUInt32(body, OwnerIdOffset);
            // Owner must be a real player id (0x00xxxxxx, non-trivial).
            if ((ownerId >> 24) != 0x00 || ownerId < 0x00010000) return;
            if (!r.Owners.ContainsKey(summonId)) r.Owners[summonId] = ownerId;
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
