-- Removes everything seed_mock_data.sql inserted, leaving genuinely
-- captured traffic untouched.
--
--   docker compose exec -T postgres psql -U hive -d hive < scripts/purge_mock_data.sql
--
-- Seeded rows are identified by their public IPs, since locally captured
-- traffic comes over the Docker bridge (172.16.0.0/12). WARNING: once this
-- is deployed publicly, real attackers also have public IPs, so running
-- this then would delete real data.

BEGIN;

CREATE TEMP TABLE mock_attacker ON COMMIT DROP AS
SELECT id FROM attackers WHERE NOT (ip_address << inet '172.16.0.0/12');

-- Children first: no FK here uses ON DELETE CASCADE.
DELETE FROM credentials
WHERE event_id IN (
  SELECT e.id FROM events e JOIN mock_attacker m ON m.id = e.attacker_id
);

DELETE FROM events WHERE attacker_id IN (SELECT id FROM mock_attacker);
DELETE FROM sessions WHERE attacker_id IN (SELECT id FROM mock_attacker);
DELETE FROM attackers WHERE id IN (SELECT id FROM mock_attacker);

-- IOCs are only ever written by the live pipeline, never by the seeder, so
-- they're all real. Drop any that referenced a purged address anyway.
DELETE FROM iocs
WHERE ioc_type = 'ip'
  AND NOT (value::inet << inet '172.16.0.0/12');

COMMIT;

SELECT
  (SELECT count(*) FROM attackers)   AS attackers_left,
  (SELECT count(*) FROM events)      AS events_left,
  (SELECT count(*) FROM sessions)    AS sessions_left,
  (SELECT count(*) FROM credentials) AS credentials_left,
  (SELECT count(*) FROM iocs)        AS iocs_left;
