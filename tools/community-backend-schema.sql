-- WS-engine Community Sync — schema Supabase
-- Rodar no Supabase SQL Editor uma vez no bootstrap do projeto.

CREATE TABLE IF NOT EXISTS entities (
  entity_id   BIGINT PRIMARY KEY,
  nick        TEXT NOT NULL,
  class_id    SMALLINT,
  client_id   TEXT NOT NULL,
  updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS ix_entities_updated ON entities(updated_at);

CREATE TABLE IF NOT EXISTS clients (
  client_id           TEXT PRIMARY KEY,
  observer_char_id    TEXT,
  observer_nick       TEXT,
  version             TEXT,
  first_seen_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_seen_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS ix_clients_last_seen ON clients(last_seen_at);

ALTER TABLE entities ENABLE ROW LEVEL SECURITY;
ALTER TABLE clients  ENABLE ROW LEVEL SECURITY;

CREATE POLICY read_all_entities ON entities FOR SELECT USING (true);
CREATE POLICY read_all_clients  ON clients  FOR SELECT USING (true);
CREATE POLICY write_entities     ON entities FOR INSERT WITH CHECK (true);
CREATE POLICY write_entities_upd ON entities FOR UPDATE USING (true);
CREATE POLICY write_clients      ON clients  FOR INSERT WITH CHECK (true);
CREATE POLICY write_clients_upd  ON clients  FOR UPDATE USING (true);
