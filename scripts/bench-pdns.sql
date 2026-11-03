-- Passive DNS lookups at production scale.
--
-- Builds a throwaway 20M-row `queries` table in the current database (run it against
-- a scratch database, never dnsmon) with the answer mix measured on a real AdGuard
-- log: 54% of rows carry addresses, ~1.8 IPs and ~0.9 CNAMEs each. IPs and domains
-- are Zipf-skewed so a few "CDN" addresses and one hot domain land in 100k+ rows,
-- the worst case for the GIN and domain lookups. Then times each lookup the API runs.
--
--   docker exec dnsmon-postgres psql -U dnsmon -d postgres -c 'CREATE DATABASE dnsmon_bench'
--   docker exec -i dnsmon-postgres psql -U dnsmon -d dnsmon_bench < scripts/bench-pdns.sql
--   docker exec dnsmon-postgres psql -U dnsmon -d postgres -c 'DROP DATABASE dnsmon_bench'
--
-- Every lookup must stay under 1 s; fix a slow one with an index or query shape,
-- never with a time cutoff (netdash needs lookups of any age).

\set rows 20000000
\timing on

DROP TABLE IF EXISTS queries;
CREATE TABLE queries (
    id bigserial PRIMARY KEY,
    timestamp timestamptz NOT NULL,
    domain varchar(255) NOT NULL,
    client_ip varchar(45) NOT NULL,
    client_hostname varchar(255),
    query_type varchar(10),
    status varchar(50),
    server varchar(100) NOT NULL,
    created_at timestamptz,
    answer_ips inet[],
    answer_cnames text[]
);

INSERT INTO queries (timestamp, domain, client_ip, query_type, status, server, answer_ips, answer_cnames)
SELECT now() - random() * interval '60 days',
       'd' || floor(power(random(), 3) * 200000)::int || '.example.com',
       '192.168.1.' || (1 + floor(random() * 60))::int,
       'A', 'ALLOWED', 'adguard' || (1 + floor(random() * 2))::int,
       CASE WHEN answered THEN (ARRAY[
             '10.0.0.0'::inet + floor(power(random(), 4) * 2000000)::int,
             '10.0.0.0'::inet + floor(power(random(), 4) * 2000000)::int,
             '10.0.0.0'::inet + floor(power(random(), 4) * 2000000)::int,
             '10.0.0.0'::inet + floor(power(random(), 4) * 2000000)::int,
             '10.0.0.0'::inet + floor(power(random(), 4) * 2000000)::int])[1:n_ips]
            ELSE '{}'::inet[] END,
       CASE WHEN answered THEN (ARRAY[
             'edge-' || floor(power(random(), 3) * 100000)::int || '.cdn.example',
             'edge-' || floor(power(random(), 3) * 100000)::int || '.cdn.example'])[1:n_cnames]
            ELSE '{}'::text[] END
FROM (SELECT random() < 0.54 AS answered,
             1 + floor(random() * random() * 5)::int AS n_ips,
             floor(random() * 2.8)::int AS n_cnames
      FROM generate_series(1, :rows)) s;

CREATE INDEX ix_queries_domain ON queries (domain);
CREATE INDEX idx_queries_timestamp_client ON queries (timestamp, client_ip);
CREATE INDEX idx_queries_answer_ips ON queries USING gin (answer_ips);
CREATE INDEX idx_queries_answer_cnames ON queries USING gin (answer_cnames);
VACUUM ANALYZE queries;

SELECT pg_size_pretty(pg_relation_size('queries')) AS heap,
       pg_size_pretty(pg_relation_size('idx_queries_answer_ips')) AS gin_ips,
       pg_size_pretty(pg_relation_size('idx_queries_answer_cnames')) AS gin_cnames,
       (SELECT count(*) FROM queries WHERE answer_ips @> ARRAY['10.0.0.0'::inet]) AS hot_ip_rows,
       (SELECT count(*) FROM queries WHERE domain = 'd0.example.com') AS hot_domain_rows;

\echo '== IP view: domains for the hottest IP (two-level, as routes/pdns.py runs it)'
EXPLAIN (ANALYZE, BUFFERS)
SELECT domain, min(first_seen), max(last_seen) AS last_seen, sum(n), array_agg(server)
FROM (SELECT domain, server, min(timestamp) AS first_seen, max(timestamp) AS last_seen, count(*) AS n
      FROM queries WHERE answer_ips @> ARRAY['10.0.0.0'::inet] GROUP BY domain, server) per_server
GROUP BY domain ORDER BY last_seen DESC LIMIT 500;

\echo '== IP view: devices for the hottest IP'
EXPLAIN (ANALYZE, BUFFERS)
SELECT client_ip, max(client_hostname), count(*), max(timestamp)
FROM queries WHERE answer_ips @> ARRAY['10.0.0.0'::inet]
GROUP BY client_ip ORDER BY max(timestamp) DESC LIMIT 500;

\echo '== Domain view: IPs for the hottest domain'
EXPLAIN (ANALYZE, BUFFERS)
SELECT value, min(ts), max(ts), count(*)
FROM (SELECT unnest(answer_ips) AS value, timestamp AS ts FROM queries
      WHERE domain = 'd0.example.com' AND answer_ips IS NOT NULL) a
GROUP BY value ORDER BY max(ts) DESC, count(*) DESC LIMIT 500;

\echo '== Resolve: hottest IP, device with a recent match'
EXPLAIN (ANALYZE, BUFFERS)
SELECT domain, timestamp, server, client_ip, answer_cnames FROM queries
WHERE answer_ips @> ARRAY['10.0.0.0'::inet] AND timestamp <= now() AND client_ip = '192.168.1.7'
ORDER BY timestamp DESC LIMIT 1;

\echo '== Resolve: hottest IP, device that never resolved it (falls through to any device)'
EXPLAIN (ANALYZE, BUFFERS)
SELECT domain, timestamp, server, client_ip, answer_cnames FROM queries
WHERE answer_ips @> ARRAY['10.0.0.0'::inet] AND timestamp <= now() AND client_ip = '192.168.9.9'
ORDER BY timestamp DESC LIMIT 1;

\echo '== Resolve: a cold IP'
EXPLAIN (ANALYZE, BUFFERS)
SELECT domain, timestamp, server, client_ip, answer_cnames FROM queries
WHERE answer_ips @> ARRAY['10.0.150.0'::inet] AND timestamp <= now()
ORDER BY timestamp DESC LIMIT 1;
