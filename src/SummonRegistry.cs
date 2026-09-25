// SummonRegistry.cs
//
// Whitelist fechada de type_ids que são invocações exclusivas de jogador.
// Origem: docs/PROTOCOL-NOTES.md + Tarefa 1 (levantamento manual pelo user).
//
// Regra: qualquer tid fora desta lista é mob normal. Não inferir classe
// nem propriedade a partir de outros tids. O byte alto do entity_id NÃO
// deve decidir se algo é invocação — só o tid decide. (Após update Warspear
// v13.4.4, o high byte migrou de 0x05 para 0x0B; qualquer código que
// dependia do range antigo quebrou. Ver PROTOCOL-NOTES.md.)

using System.Collections.Generic;

namespace WSEngine
{
    internal class SummonInfo
    {
        public int Tid;
        public string Name;
        public int OwnerClassId;
        public string OwnerClassName;

        public SummonInfo(int tid, string name, int classId, string className)
        {
            Tid = tid;
            Name = name;
            OwnerClassId = classId;
            OwnerClassName = className;
        }
    }

    internal static class SummonRegistry
    {
        public static readonly Dictionary<int, SummonInfo> ByTid = new Dictionary<int, SummonInfo>
        {
            { 6547,  new SummonInfo(6547,  "Lobo Escuridão",         19, "Invocador de Feras") },
            { 10583, new SummonInfo(10583, "Esqueleto",              11, "Necromante") },
            { 21812, new SummonInfo(21812, "Esqueleto Arqueiro",     11, "Necromante") },
            { 21813, new SummonInfo(21813, "Esqueleto Amaldiçoado",  11, "Necromante") },
        };

        public static bool IsSummonTid(int tid) { return ByTid.ContainsKey(tid); }

        public static SummonInfo Get(int tid)
        {
            SummonInfo info;
            return ByTid.TryGetValue(tid, out info) ? info : null;
        }
    }
}
