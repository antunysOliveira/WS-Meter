// ==================== Fase 9 — SQLite persistence ====================
//
// Local durable catalog + raw-message log so name/class data survives across
// sessions and captures can be reprocessed with a corrected decoder later.
//
// Design principle: store the RAW TLV message (tag + body bytes). Derived
// tables (damage_events) can be dropped and regenerated from raw_messages
// when the decoder changes — no data loss when the interpretation improves.
//
// Runtime: System.Data.SQLite (managed wrapper) + SQLite.Interop.dll (native
// x64). Both live in libs/ and are referenced by build.bat. NO NuGet, NO SDK
// — matches the existing csc.exe workflow.
//
// Batched inserts: everything goes through _pendingRaw / _pendingDamage
// buffers, flushed inside a single transaction. SQLite row-by-row inserts
// via ADO.NET peak at ~200 ops/sec on Windows; batched hits ~50k/sec.

using System;
using System.Collections.Generic;
using System.Data.SQLite;
using System.IO;
using System.Text.RegularExpressions;

namespace WSEngine
{
    class EntityRecord
    {
        public uint EntityId;
        public string Name;
        public int? ClassId;
        public string Guild;
        public long PrimeiroVisto;
        public long UltimoVisto;
        public string Fonte;
    }

    class SessionRecord
    {
        public long Id;
        public long IniciadaEm;
        public long? EncerradaEm;
        public string PcapPath;
    }

    class Database : IDisposable
    {
        readonly string _path;
        SQLiteConnection _conn;
        long _currentSessionId;
        readonly HashSet<int> _seenStreamPos = new HashSet<int>();

        // Batched insert buffers
        readonly List<RawRow> _pendingRaw = new List<RawRow>();
        readonly List<DmgRow> _pendingDamage = new List<DmgRow>();
        const int MaxBufferSize = 500;

        struct RawRow { public long Ts; public int Tag; public byte[] Body; }
        struct DmgRow { public long Ts; public long AttId; public long TgtId; public long Amount; public string Origem; }

        public Database(string path)
        {
            _path = path;
            _conn = new SQLiteConnection("Data Source=" + path + ";Version=3;");
            _conn.Open();
            using (var cmd = _conn.CreateCommand())
            {
                cmd.CommandText = "PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;";
                cmd.ExecuteNonQuery();
            }
            CreateSchema();
        }

        void CreateSchema()
        {
            const string sql =
                "CREATE TABLE IF NOT EXISTS sessions (" +
                "  id INTEGER PRIMARY KEY AUTOINCREMENT," +
                "  iniciada_em INTEGER NOT NULL," +
                "  encerrada_em INTEGER," +
                "  pcap_path TEXT" +
                ");" +
                "CREATE TABLE IF NOT EXISTS raw_messages (" +
                "  id INTEGER PRIMARY KEY AUTOINCREMENT," +
                "  session_id INTEGER NOT NULL," +
                "  ts INTEGER NOT NULL," +
                "  tag INTEGER NOT NULL," +
                "  body BLOB" +
                ");" +
                "CREATE INDEX IF NOT EXISTS ix_raw_session_tag ON raw_messages(session_id, tag);" +
                "CREATE INDEX IF NOT EXISTS ix_raw_ts ON raw_messages(ts);" +
                "CREATE TABLE IF NOT EXISTS entities (" +
                "  entity_id INTEGER PRIMARY KEY," +
                "  nome TEXT," +
                "  class_id INTEGER," +
                "  guilda TEXT," +
                "  primeiro_visto INTEGER," +
                "  ultimo_visto INTEGER," +
                "  fonte TEXT" +
                ");" +
                "CREATE INDEX IF NOT EXISTS ix_entities_nome ON entities(nome);" +
                "CREATE TABLE IF NOT EXISTS damage_events (" +
                "  id INTEGER PRIMARY KEY AUTOINCREMENT," +
                "  session_id INTEGER NOT NULL," +
                "  ts INTEGER NOT NULL," +
                "  attacker_id INTEGER," +
                "  target_id INTEGER," +
                "  amount INTEGER NOT NULL," +
                "  origem TEXT" +
                ");" +
                "CREATE INDEX IF NOT EXISTS ix_dmg_session ON damage_events(session_id);" +
                "CREATE INDEX IF NOT EXISTS ix_dmg_att ON damage_events(attacker_id);" +
                "CREATE TABLE IF NOT EXISTS bouts (" +
                "  id INTEGER PRIMARY KEY AUTOINCREMENT," +
                "  session_id INTEGER NOT NULL," +
                "  iniciada_em INTEGER NOT NULL," +
                "  encerrada_em INTEGER," +
                "  raw_id_min INTEGER," +
                "  raw_id_max INTEGER," +
                "  label TEXT" +
                ");" +
                "CREATE INDEX IF NOT EXISTS ix_bouts_session ON bouts(session_id);";
            using (var cmd = _conn.CreateCommand())
            {
                cmd.CommandText = sql;
                cmd.ExecuteNonQuery();
            }
        }

        public long StartSession(string pcapPath)
        {
            FlushInternal();
            _seenStreamPos.Clear();
            long now = UnixMs();
            using (var cmd = _conn.CreateCommand())
            {
                cmd.CommandText = "INSERT INTO sessions(iniciada_em, pcap_path) VALUES(@t, @p); SELECT last_insert_rowid();";
                cmd.Parameters.AddWithValue("@t", now);
                cmd.Parameters.AddWithValue("@p", pcapPath ?? "");
                _currentSessionId = (long)cmd.ExecuteScalar();
            }
            return _currentSessionId;
        }

        public void EndSession()
        {
            FlushInternal();
            if (_currentSessionId <= 0) return;
            long now = UnixMs();
            using (var cmd = _conn.CreateCommand())
            {
                cmd.CommandText = "UPDATE sessions SET encerrada_em=@t WHERE id=@id";
                cmd.Parameters.AddWithValue("@t", now);
                cmd.Parameters.AddWithValue("@id", _currentSessionId);
                cmd.ExecuteNonQuery();
            }
            _currentSessionId = 0;
            _seenStreamPos.Clear();
        }

        public long CurrentSessionId { get { return _currentSessionId; } }

        // Bouts API — logical fight segments inside a physical capture session.
        // A bout carries [raw_id_min, raw_id_max] pointing into raw_messages so any
        // fight can be reprocessed by replaying that range through the current decoder.
        public long StartBout(string label)
        {
            if (_currentSessionId <= 0) return 0;
            FlushInternal();
            long now = UnixMs();
            long rawMin = ScalarLong("SELECT COALESCE(MAX(id)+1, 1) FROM raw_messages");
            using (var cmd = _conn.CreateCommand())
            {
                cmd.CommandText = "INSERT INTO bouts(session_id, iniciada_em, raw_id_min, label) VALUES(@s, @t, @r, @l); SELECT last_insert_rowid();";
                cmd.Parameters.AddWithValue("@s", _currentSessionId);
                cmd.Parameters.AddWithValue("@t", now);
                cmd.Parameters.AddWithValue("@r", rawMin);
                cmd.Parameters.AddWithValue("@l", (object)label ?? DBNull.Value);
                return (long)cmd.ExecuteScalar();
            }
        }

        public void EndBout(long boutId)
        {
            if (boutId <= 0) return;
            FlushInternal();
            long now = UnixMs();
            long rawMax = ScalarLong("SELECT COALESCE(MAX(id), 0) FROM raw_messages");
            using (var cmd = _conn.CreateCommand())
            {
                cmd.CommandText = "UPDATE bouts SET encerrada_em=@t, raw_id_max=@r WHERE id=@id";
                cmd.Parameters.AddWithValue("@t", now);
                cmd.Parameters.AddWithValue("@r", rawMax);
                cmd.Parameters.AddWithValue("@id", boutId);
                cmd.ExecuteNonQuery();
            }
        }

        public List<Tuple<long,long,long,string>> ListBouts(long sessionId)
        {
            var list = new List<Tuple<long,long,long,string>>();
            using (var cmd = _conn.CreateCommand())
            {
                cmd.CommandText = "SELECT id, iniciada_em, COALESCE(encerrada_em,0), COALESCE(label,'') FROM bouts WHERE session_id=@s ORDER BY id DESC";
                cmd.Parameters.AddWithValue("@s", sessionId);
                using (var r = cmd.ExecuteReader())
                    while (r.Read()) list.Add(Tuple.Create(r.GetInt64(0), r.GetInt64(1), r.GetInt64(2), r.GetString(3)));
            }
            return list;
        }

        // Insert a batch of TlvMessages, skipping already-seen ones by StreamPos.
        // Direction is filtered by the caller (typically only s2c is stored).
        public int InsertRawBatch(IList<TlvMessage> msgs)
        {
            if (msgs == null || _currentSessionId <= 0) return 0;
            int added = 0;
            foreach (var m in msgs)
            {
                if (m == null || m.Body == null) continue;
                if (!_seenStreamPos.Add(m.StreamPos)) continue;
                long ts = (long)(m.Time * 1000.0);
                _pendingRaw.Add(new RawRow { Ts = ts, Tag = m.Tag, Body = m.Body });
                added++;
            }
            if (_pendingRaw.Count >= MaxBufferSize) FlushRaw();
            return added;
        }

        public void InsertDamage(long ts, uint att, uint tgt, uint amount, string origem)
        {
            if (_currentSessionId <= 0) return;
            _pendingDamage.Add(new DmgRow { Ts = ts, AttId = att, TgtId = tgt, Amount = amount, Origem = origem });
            if (_pendingDamage.Count >= MaxBufferSize) FlushDamage();
        }

        public void UpsertEntity(uint entityId, string name, int? classId, string guild, string fonte)
        {
            if (entityId == 0) return;
            long now = UnixMs();
            using (var cmd = _conn.CreateCommand())
            {
                cmd.CommandText =
                    "INSERT INTO entities(entity_id, nome, class_id, guilda, primeiro_visto, ultimo_visto, fonte) " +
                    "VALUES(@id, @n, @c, @g, @t, @t, @f) " +
                    "ON CONFLICT(entity_id) DO UPDATE SET " +
                    "  nome = COALESCE(excluded.nome, entities.nome), " +
                    "  class_id = COALESCE(excluded.class_id, entities.class_id), " +
                    "  guilda = COALESCE(excluded.guilda, entities.guilda), " +
                    "  ultimo_visto = MAX(excluded.ultimo_visto, entities.ultimo_visto), " +
                    "  fonte = excluded.fonte";
                cmd.Parameters.AddWithValue("@id", (long)entityId);
                cmd.Parameters.AddWithValue("@n", (object)name ?? DBNull.Value);
                cmd.Parameters.AddWithValue("@c", classId.HasValue ? (object)classId.Value : DBNull.Value);
                cmd.Parameters.AddWithValue("@g", (object)guild ?? DBNull.Value);
                cmd.Parameters.AddWithValue("@t", now);
                cmd.Parameters.AddWithValue("@f", (object)fonte ?? DBNull.Value);
                cmd.ExecuteNonQuery();
            }
        }

        // Batched upsert for migration / bulk maps.
        public int UpsertEntitiesBatch(IEnumerable<EntityRecord> records)
        {
            int count = 0;
            using (var tx = _conn.BeginTransaction())
            using (var cmd = _conn.CreateCommand())
            {
                cmd.Transaction = tx;
                cmd.CommandText =
                    "INSERT INTO entities(entity_id, nome, class_id, guilda, primeiro_visto, ultimo_visto, fonte) " +
                    "VALUES(@id, @n, @c, @g, @t, @t, @f) " +
                    "ON CONFLICT(entity_id) DO UPDATE SET " +
                    "  nome = COALESCE(excluded.nome, entities.nome), " +
                    "  class_id = COALESCE(excluded.class_id, entities.class_id), " +
                    "  guilda = COALESCE(excluded.guilda, entities.guilda), " +
                    "  ultimo_visto = MAX(excluded.ultimo_visto, entities.ultimo_visto), " +
                    "  fonte = excluded.fonte";
                var pId = cmd.Parameters.Add("@id", System.Data.DbType.Int64);
                var pN = cmd.Parameters.Add("@n", System.Data.DbType.String);
                var pC = cmd.Parameters.Add("@c", System.Data.DbType.Int32);
                var pG = cmd.Parameters.Add("@g", System.Data.DbType.String);
                var pT = cmd.Parameters.Add("@t", System.Data.DbType.Int64);
                var pF = cmd.Parameters.Add("@f", System.Data.DbType.String);
                long now = UnixMs();
                foreach (var r in records)
                {
                    if (r == null || r.EntityId == 0) continue;
                    pId.Value = (long)r.EntityId;
                    pN.Value = (object)r.Name ?? DBNull.Value;
                    pC.Value = r.ClassId.HasValue ? (object)r.ClassId.Value : DBNull.Value;
                    pG.Value = (object)r.Guild ?? DBNull.Value;
                    pT.Value = r.UltimoVisto == 0 ? now : r.UltimoVisto;
                    pF.Value = (object)r.Fonte ?? DBNull.Value;
                    cmd.ExecuteNonQuery();
                    count++;
                }
                tx.Commit();
            }
            return count;
        }

        public EntityRecord LookupEntity(uint entityId)
        {
            using (var cmd = _conn.CreateCommand())
            {
                cmd.CommandText = "SELECT entity_id, nome, class_id, guilda, primeiro_visto, ultimo_visto, fonte FROM entities WHERE entity_id=@id";
                cmd.Parameters.AddWithValue("@id", (long)entityId);
                using (var r = cmd.ExecuteReader())
                {
                    if (!r.Read()) return null;
                    return new EntityRecord
                    {
                        EntityId = (uint)r.GetInt64(0),
                        Name = r.IsDBNull(1) ? null : r.GetString(1),
                        ClassId = r.IsDBNull(2) ? (int?)null : r.GetInt32(2),
                        Guild = r.IsDBNull(3) ? null : r.GetString(3),
                        PrimeiroVisto = r.IsDBNull(4) ? 0 : r.GetInt64(4),
                        UltimoVisto = r.IsDBNull(5) ? 0 : r.GetInt64(5),
                        Fonte = r.IsDBNull(6) ? null : r.GetString(6)
                    };
                }
            }
        }

        // Bulk load all entities into a dictionary — used to seed nameMap/classMap
        // at boot without paying per-lookup cost during LivePoll.
        public Dictionary<uint, EntityRecord> LoadAllEntities()
        {
            var d = new Dictionary<uint, EntityRecord>();
            using (var cmd = _conn.CreateCommand())
            {
                cmd.CommandText = "SELECT entity_id, nome, class_id, guilda, primeiro_visto, ultimo_visto, fonte FROM entities";
                using (var r = cmd.ExecuteReader())
                {
                    while (r.Read())
                    {
                        uint id = (uint)r.GetInt64(0);
                        d[id] = new EntityRecord
                        {
                            EntityId = id,
                            Name = r.IsDBNull(1) ? null : r.GetString(1),
                            ClassId = r.IsDBNull(2) ? (int?)null : r.GetInt32(2),
                            Guild = r.IsDBNull(3) ? null : r.GetString(3),
                            PrimeiroVisto = r.IsDBNull(4) ? 0 : r.GetInt64(4),
                            UltimoVisto = r.IsDBNull(5) ? 0 : r.GetInt64(5),
                            Fonte = r.IsDBNull(6) ? null : r.GetString(6)
                        };
                    }
                }
            }
            return d;
        }

        public void Flush() { FlushInternal(); }

        void FlushInternal()
        {
            FlushRaw();
            FlushDamage();
        }

        void FlushRaw()
        {
            if (_pendingRaw.Count == 0 || _currentSessionId <= 0) return;
            using (var tx = _conn.BeginTransaction())
            using (var cmd = _conn.CreateCommand())
            {
                cmd.Transaction = tx;
                cmd.CommandText = "INSERT INTO raw_messages(session_id, ts, tag, body) VALUES(@s, @ts, @tag, @body)";
                var pS = cmd.Parameters.Add("@s", System.Data.DbType.Int64);
                var pTs = cmd.Parameters.Add("@ts", System.Data.DbType.Int64);
                var pTag = cmd.Parameters.Add("@tag", System.Data.DbType.Int32);
                var pBody = cmd.Parameters.Add("@body", System.Data.DbType.Binary);
                pS.Value = _currentSessionId;
                foreach (var r in _pendingRaw)
                {
                    pTs.Value = r.Ts;
                    pTag.Value = r.Tag;
                    pBody.Value = r.Body;
                    cmd.ExecuteNonQuery();
                }
                tx.Commit();
            }
            _pendingRaw.Clear();
        }

        void FlushDamage()
        {
            if (_pendingDamage.Count == 0 || _currentSessionId <= 0) return;
            using (var tx = _conn.BeginTransaction())
            using (var cmd = _conn.CreateCommand())
            {
                cmd.Transaction = tx;
                cmd.CommandText = "INSERT INTO damage_events(session_id, ts, attacker_id, target_id, amount, origem) VALUES(@s, @ts, @a, @t, @amt, @o)";
                var pS = cmd.Parameters.Add("@s", System.Data.DbType.Int64);
                var pTs = cmd.Parameters.Add("@ts", System.Data.DbType.Int64);
                var pA = cmd.Parameters.Add("@a", System.Data.DbType.Int64);
                var pT = cmd.Parameters.Add("@t", System.Data.DbType.Int64);
                var pAmt = cmd.Parameters.Add("@amt", System.Data.DbType.Int64);
                var pO = cmd.Parameters.Add("@o", System.Data.DbType.String);
                pS.Value = _currentSessionId;
                foreach (var r in _pendingDamage)
                {
                    pTs.Value = r.Ts;
                    pA.Value = r.AttId;
                    pT.Value = r.TgtId;
                    pAmt.Value = r.Amount;
                    pO.Value = (object)r.Origem ?? DBNull.Value;
                    cmd.ExecuteNonQuery();
                }
                tx.Commit();
            }
            _pendingDamage.Clear();
        }

        // Import legacy JSON files into entities. Returns count imported.
        public int ImportLegacyJsons(string root)
        {
            var byId = new Dictionary<uint, EntityRecord>();

            string namesPath = Path.Combine(root, "ws-engine.mem-players.json");
            if (File.Exists(namesPath))
            {
                var rx = new Regex("\"0x([0-9A-Fa-f]+)\"\\s*:\\s*\"([^\"]*)\"");
                foreach (Match m in rx.Matches(File.ReadAllText(namesPath)))
                {
                    uint id = Convert.ToUInt32(m.Groups[1].Value, 16);
                    if (!byId.ContainsKey(id)) byId[id] = new EntityRecord { EntityId = id, Fonte = "memscan" };
                    byId[id].Name = m.Groups[2].Value;
                }
            }

            string classesPath = Path.Combine(root, "ws-engine.mem-player-classes.json");
            if (File.Exists(classesPath))
            {
                var rx = new Regex("\"0x([0-9A-Fa-f]+)\"\\s*:\\s*(\\d+)");
                foreach (Match m in rx.Matches(File.ReadAllText(classesPath)))
                {
                    uint id = Convert.ToUInt32(m.Groups[1].Value, 16);
                    if (!byId.ContainsKey(id)) byId[id] = new EntityRecord { EntityId = id, Fonte = "memscan" };
                    byId[id].ClassId = int.Parse(m.Groups[2].Value);
                }
            }

            string guildsPath = Path.Combine(root, "ws-engine.mem-player-guilds.json");
            if (File.Exists(guildsPath))
            {
                var rx = new Regex("\"0x([0-9A-Fa-f]+)\"\\s*:\\s*\"([^\"]*)\"");
                foreach (Match m in rx.Matches(File.ReadAllText(guildsPath)))
                {
                    uint id = Convert.ToUInt32(m.Groups[1].Value, 16);
                    if (!byId.ContainsKey(id)) byId[id] = new EntityRecord { EntityId = id, Fonte = "memscan" };
                    byId[id].Guild = m.Groups[2].Value;
                }
            }

            return UpsertEntitiesBatch(byId.Values);
        }

        // Growth stats: total DB size on disk + row counts.
        public string StatsSummary()
        {
            long dbBytes = 0;
            try { dbBytes = new FileInfo(_path).Length; } catch { }
            long rawRows = ScalarLong("SELECT COUNT(*) FROM raw_messages");
            long entRows = ScalarLong("SELECT COUNT(*) FROM entities");
            long dmgRows = ScalarLong("SELECT COUNT(*) FROM damage_events");
            long sesRows = ScalarLong("SELECT COUNT(*) FROM sessions");
            return string.Format(
                "db {0:F1} MB | sessions {1} | raw {2} | entities {3} | damage {4}",
                dbBytes / 1048576.0, sesRows, rawRows, entRows, dmgRows);
        }

        long ScalarLong(string sql)
        {
            using (var cmd = _conn.CreateCommand())
            {
                cmd.CommandText = sql;
                var v = cmd.ExecuteScalar();
                return v == null || v == DBNull.Value ? 0 : Convert.ToInt64(v);
            }
        }

        static readonly DateTime _unixEpoch = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);
        static long UnixMs()
        {
            return (long)(DateTime.UtcNow - _unixEpoch).TotalMilliseconds;
        }

        public void Dispose()
        {
            try { FlushInternal(); } catch { }
            try { if (_conn != null) _conn.Close(); } catch { }
            try { if (_conn != null) _conn.Dispose(); } catch { }
            _conn = null;
        }
    }
}
