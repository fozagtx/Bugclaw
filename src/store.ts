import { chmodSync, closeSync, mkdirSync, openSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { randomUUID } from "node:crypto";
import { config } from "./config.ts";

export class Store {
	readonly db: DatabaseSync;
	constructor(file = resolve(config().dataDir, "bugclaw.sqlite")) {
		mkdirSync(dirname(file), { recursive: true, mode: 0o700 });
		const handle = openSync(file, "a", 0o600);
		closeSync(handle);
		chmodSync(file, 0o600);
		this.db = new DatabaseSync(file);
		this.db.exec(`
			PRAGMA journal_mode=WAL;
			CREATE TABLE IF NOT EXISTS scans(id TEXT PRIMARY KEY, status TEXT NOT NULL, source TEXT NOT NULL, authorization TEXT NOT NULL, snapshot_hash TEXT, report TEXT, created_at TEXT NOT NULL);
			CREATE TABLE IF NOT EXISTS candidates(id TEXT PRIMARY KEY, scan_id TEXT NOT NULL, status TEXT NOT NULL, severity TEXT, title TEXT, data TEXT NOT NULL, FOREIGN KEY(scan_id) REFERENCES scans(id));
			CREATE TABLE IF NOT EXISTS attempts(id TEXT PRIMARY KEY, candidate_id TEXT NOT NULL, step TEXT NOT NULL, status TEXT NOT NULL, result TEXT NOT NULL, created_at TEXT NOT NULL);
			CREATE TABLE IF NOT EXISTS signoffs(id TEXT PRIMARY KEY, candidate_id TEXT NOT NULL, decision TEXT NOT NULL CHECK(decision IN ('confirmed','rejected')), note TEXT NOT NULL, at TEXT NOT NULL);
		`);
	}
	createScan(row: { id: string; source: string; authorization: string }) {
		this.db.prepare("INSERT INTO scans(id,status,source,authorization,created_at) VALUES(?,?,?,?,?)").run(row.id,"queued",row.source,row.authorization,new Date().toISOString());
	}
	setScan(id: string, status: string, snapshotHash?: string, report?: unknown) {
		this.db.prepare("UPDATE scans SET status=?,snapshot_hash=COALESCE(?,snapshot_hash),report=COALESCE(?,report) WHERE id=?").run(status,snapshotHash,report ? JSON.stringify(report) : null,id);
	}
	putCandidate(scanId: string, c: Record<string, unknown>) {
		this.db.prepare("INSERT OR REPLACE INTO candidates(id,scan_id,status,severity,title,data) VALUES(?,?,?,?,?,?)").run(String(c.id),scanId,String(c.status ?? "unvalidated"),String(c.severity ?? ""),String(c.title ?? ""),JSON.stringify(c));
	}
	setCandidateStatus(id: string, status: string, data: unknown) {
		this.db.prepare("UPDATE candidates SET status=?,data=? WHERE id=?").run(status,JSON.stringify(data),id);
	}
	scan(id: string) { return this.db.prepare("SELECT * FROM scans WHERE id=?").get(id); }
	scans() {
		return this.db.prepare(`
			SELECT scans.id,scans.status,scans.source,scans.created_at,scans.snapshot_hash,COUNT(candidates.id) AS candidateCount
			FROM scans LEFT JOIN candidates ON candidates.scan_id=scans.id
			GROUP BY scans.id,scans.status,scans.source,scans.created_at,scans.snapshot_hash
			ORDER BY scans.created_at DESC
		`).all();
	}
	recentActivity(limit = 20) {
		const size = Number.isFinite(limit) ? Math.max(1, Math.min(50, Math.trunc(limit))) : 20;
		const scans = this.db.prepare("SELECT created_at AS at,'scan' AS kind,status,id AS scanId,source AS title FROM scans ORDER BY created_at DESC LIMIT ?").all(size);
		const attempts = this.db.prepare(`
			SELECT attempts.created_at AS at,'attempt' AS kind,attempts.step,attempts.status AS rowStatus,attempts.result,
				candidates.scan_id AS scanId,candidates.id AS candidateId,candidates.title
			FROM attempts JOIN candidates ON candidates.id=attempts.candidate_id
			ORDER BY attempts.created_at DESC LIMIT ?
		`).all(size).map((row: any) => {
			let result: any = {};
			try { result = JSON.parse(row.result); } catch {}
			return {
				at: row.at,
				kind: row.kind,
				step: row.step,
				status: String(result?.status ?? result?.verdict ?? row.rowStatus),
				scanId: row.scanId,
				candidateId: row.candidateId,
				title: row.title,
			};
		});
		const signoffs = this.db.prepare(`
			SELECT signoffs.at AS at,'signoff' AS kind,signoffs.decision AS status,
				candidates.scan_id AS scanId,candidates.id AS candidateId,candidates.title
			FROM signoffs JOIN candidates ON candidates.id=signoffs.candidate_id
			ORDER BY signoffs.at DESC LIMIT ?
		`).all(size);
		return [...scans, ...attempts, ...signoffs]
			.sort((a: any, b: any) => String(b.at).localeCompare(String(a.at)))
			.slice(0, size);
	}
	candidates(scanId?: string) { return scanId ? this.db.prepare("SELECT * FROM candidates WHERE scan_id=? ORDER BY id").all(scanId) : this.db.prepare("SELECT * FROM candidates ORDER BY scan_id,id").all(); }
	candidate(id: string) { return this.db.prepare("SELECT * FROM candidates WHERE id=?").get(id) as any; }
	attempt(candidateId: string, step: string, result: unknown) {
		this.db.prepare("INSERT INTO attempts VALUES(?,?,?,?,?,?)").run(randomUUID(),candidateId,step,"done",JSON.stringify(result),new Date().toISOString());
	}
	attempts(candidateId: string) { return this.db.prepare("SELECT * FROM attempts WHERE candidate_id=? ORDER BY created_at").all(candidateId); }
	signoffs(candidateId: string) { return this.db.prepare("SELECT * FROM signoffs WHERE candidate_id=? ORDER BY at").all(candidateId); }
	signoff(candidateId: string, decision: "confirmed"|"rejected", note: string) {
		this.db.prepare("INSERT INTO signoffs VALUES(?,?,?,?,?)").run(randomUUID(),candidateId,decision,note,new Date().toISOString());
	}
	close() { this.db.close(); }
}
