//! History store: list what a browser has visited, and merge an incoming set into it.
//!
//! Payload shape is: `{"urls": [...], "visits": [...]}`. Visits name
//! their URL by string and their referrer by the referrer's `visit_time`; row ids never leave
//! the database.
//!
//! Merge rule (A into B and B into A converge on the same content):
//! - URLs are matched by string. Title: the longer wins, ties broken lexicographically.
//!   `typed_count` and `last_visit_time` take the max. `hidden` takes the max too (the
//!   reference kept the local flag, which depends on direction).
//! - Visits are matched by (url, visit_time). `visit_count` and `last_visit_time` are never
//!   trusted from the box: they are recomputed from the visit rows for every URL touched.
//! - A duplicate visit keeps the larger of (visit_duration, transition, from_visit_time),
//!   a total order, where the reference kept whichever copy the database already had.
//! - Referrers are resolved in a second pass, after every visit is in, so the result does not
//!   depend on insert order. A referrer time shared by several visits resolves to the one
//!   with the smallest (url, id). An unresolvable referrer is written as 0 and counted.
//! - Row ids and `segment_id` are local and never compared.

use std::collections::{HashMap, HashSet};
use std::path::Path;
#[cfg(test)]
use std::path::PathBuf;

use rusqlite::{Connection, OpenFlags, OptionalExtension, TransactionBehavior};
use serde::{Deserialize, Serialize};

use crate::cookies::sql;
#[cfg(test)]
use crate::Error;
use crate::Result;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HistoryUrl {
    pub url: String,
    #[serde(default)]
    pub title: String,
    #[serde(default)]
    pub typed_count: i64,
    #[serde(default)]
    pub last_visit_time: i64,
    #[serde(default)]
    pub hidden: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Visit {
    pub url: String,
    pub visit_time: i64,
    /// `null` when the visit had no referrer (or it was pruned away).
    #[serde(default)]
    pub from_visit_time: Option<i64>,
    #[serde(default)]
    pub transition: i64,
    #[serde(default)]
    pub visit_duration: i64,
}

impl Visit {
    /// Which copy of a duplicate visit wins: larger wins; None sorts below any referrer.
    fn rank(&self) -> (i64, i64, Option<i64>) {
        (self.visit_duration, self.transition, self.from_visit_time)
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Section {
    #[serde(default)]
    pub urls: Vec<HistoryUrl>,
    #[serde(default)]
    pub visits: Vec<Visit>,
}

#[derive(Debug, Default, PartialEq, Eq, Serialize)]
pub struct Stats {
    pub urls_inserted: usize,
    pub urls_updated: usize,
    pub visits_inserted: usize,
    pub visits_skipped: usize,
    /// Duplicate visits where the incoming copy outranked the local one and replaced its fields.
    pub visits_updated: usize,
    pub from_visit_zeroed: usize,
}

/// Read every URL and visit. Works on a snapshot copy (db plus -wal/-shm) so a running browser
/// is never disturbed. A missing file is an empty section; an unreadable one is an error.
pub fn export(path: &Path) -> Result<Section> {
    if !path.exists() {
        return Ok(Section::default());
    }
    let (_scratch, copy) = crate::util::snapshot_db(path)?;
    let con = Connection::open(&copy).map_err(sql)?;
    read_section(&con)
}

fn read_section(con: &Connection) -> Result<Section> {
    let mut st = con
        .prepare("SELECT id, url, title, typed_count, last_visit_time, hidden FROM urls ORDER BY url, id")
        .map_err(sql)?;
    let url_rows = st
        .query_map([], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, Option<String>>(2)?.unwrap_or_default(),
                r.get::<_, i64>(3)?,
                r.get::<_, i64>(4)?,
                r.get::<_, i64>(5)?,
            ))
        })
        .map_err(sql)?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(sql)?;
    let mut st = con
        .prepare("SELECT url, visit_time, from_visit, transition, visit_duration FROM visits ORDER BY visit_time, url, id")
        .map_err(sql)?;
    let visit_rows = st
        .query_map([], |r| {
            Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?, r.get::<_, i64>(2)?, r.get::<_, i64>(3)?, r.get::<_, i64>(4)?))
        })
        .map_err(sql)?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(sql)?;
    let mut st = con.prepare("SELECT id, visit_time FROM visits ORDER BY id").map_err(sql)?;
    let time_by_id: HashMap<i64, i64> = st
        .query_map([], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?)))
        .map_err(sql)?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(sql)?
        .into_iter()
        .collect();

    let url_by_id: HashMap<i64, &str> = url_rows.iter().map(|r| (r.0, r.1.as_str())).collect();
    let urls = url_rows
        .iter()
        .map(|r| HistoryUrl { url: r.1.clone(), title: r.2.clone(), typed_count: r.3, last_visit_time: r.4, hidden: r.5 })
        .collect();
    let mut visits = Vec::new();
    for (url_id, vtime, from_id, transition, duration) in visit_rows {
        // A visit whose URL row is gone carries nothing.
        let Some(url) = url_by_id.get(&url_id) else { continue };
        let from_visit_time = if from_id != 0 { time_by_id.get(&from_id).copied() } else { None };
        visits.push(Visit {
            url: (*url).to_string(),
            visit_time: vtime,
            from_visit_time,
            transition,
            visit_duration: duration,
        });
    }
    Ok(Section { urls, visits })
}

struct LocalUrl {
    id: i64,
    title: String,
    typed_count: i64,
    last_visit_time: i64,
    hidden: i64,
}

/// Merge `section` into an open History connection; the caller owns the transaction.
pub fn merge(con: &Connection, section: &Section) -> Result<Stats> {
    let mut stats = Stats::default();
    let mut local: HashMap<String, LocalUrl> = HashMap::new();
    {
        let mut st = con
            .prepare("SELECT id, url, title, typed_count, last_visit_time, hidden FROM urls ORDER BY id")
            .map_err(sql)?;
        let rows = st
            .query_map([], |r| {
                Ok((
                    r.get::<_, String>(1)?,
                    LocalUrl {
                        id: r.get(0)?,
                        title: r.get::<_, Option<String>>(2)?.unwrap_or_default(),
                        typed_count: r.get(3)?,
                        last_visit_time: r.get(4)?,
                        hidden: r.get(5)?,
                    },
                ))
            })
            .map_err(sql)?;
        for row in rows {
            let (url, lu) = row.map_err(sql)?;
            local.entry(url).or_insert(lu);
        }
    }
    let mut url_id: HashMap<String, i64> = HashMap::new();
    let mut merged_last: HashMap<i64, i64> = HashMap::new();
    let mut touched: Vec<i64> = Vec::new();

    let mut note_url = |url: &str, title: &str, typed: i64, last: i64, hidden: i64| -> Result<i64> {
        if let Some(id) = url_id.get(url) {
            return Ok(*id);
        }
        let lid = if let Some(row) = local.get(url) {
            let mut best = row.title.as_str();
            if !title.is_empty() && (title.chars().count(), title) > (best.chars().count(), best) {
                best = title;
            }
            let new_last = row.last_visit_time.max(last);
            let new_typed = row.typed_count.max(typed);
            let new_hidden = row.hidden.max(hidden);
            if best != row.title || new_last != row.last_visit_time || new_typed != row.typed_count || new_hidden != row.hidden {
                con.execute(
                    "UPDATE urls SET title=?1, typed_count=?2, last_visit_time=?3, hidden=?4 WHERE id=?5",
                    (best, new_typed, new_last, new_hidden, row.id),
                )
                .map_err(sql)?;
                stats.urls_updated += 1;
            }
            merged_last.insert(row.id, new_last);
            row.id
        } else {
            con.execute(
                "INSERT INTO urls (url, title, visit_count, typed_count, last_visit_time, hidden) VALUES (?1,?2,0,?3,?4,?5)",
                (url, title, typed, last, hidden),
            )
            .map_err(sql)?;
            let id = con.last_insert_rowid();
            merged_last.insert(id, last);
            stats.urls_inserted += 1;
            id
        };
        url_id.insert(url.to_string(), lid);
        touched.push(lid);
        Ok(lid)
    };

    for u in &section.urls {
        note_url(&u.url, &u.title, u.typed_count, u.last_visit_time, u.hidden)?;
    }

    // (url id, visit_time) -> (visit id, local from_visit_time, same ranking shape as Visit::rank).
    let mut existing: HashMap<(i64, i64), (i64, (i64, i64, Option<i64>))> = HashMap::new();
    {
        let mut st = con
            .prepare(
                "SELECT v.id, v.url, v.visit_time, v.visit_duration, v.transition, f.visit_time \
                 FROM visits v LEFT JOIN visits f ON f.id = v.from_visit AND v.from_visit != 0 ORDER BY v.id",
            )
            .map_err(sql)?;
        let rows = st
            .query_map([], |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, i64>(1)?,
                    r.get::<_, i64>(2)?,
                    r.get::<_, i64>(3)?,
                    r.get::<_, i64>(4)?,
                    r.get::<_, Option<i64>>(5)?,
                ))
            })
            .map_err(sql)?;
        for row in rows {
            let (id, url, time, dur, tr, from) = row.map_err(sql)?;
            existing.entry((url, time)).or_insert((id, (dur, tr, from)));
        }
    }

    // Pass 1: every visit in, in a fixed order. Pass 2 links referrers.
    let mut visits: Vec<&Visit> = section.visits.iter().collect();
    visits.sort_by(|a, b| (a.visit_time, &a.url).cmp(&(b.visit_time, &b.url)));
    let mut to_link: Vec<(i64, i64, i64)> = Vec::new(); // (visit id, visit_time, from_visit_time)
    for v in visits {
        let lid = note_url(&v.url, "", 0, v.visit_time, 0)?;
        if let Some((vid, local_rank)) = existing.get(&(lid, v.visit_time)).copied() {
            stats.visits_skipped += 1;
            if v.rank() > local_rank {
                con.execute(
                    "UPDATE visits SET transition=?1, visit_duration=?2, from_visit=0 WHERE id=?3",
                    (v.transition, v.visit_duration, vid),
                )
                .map_err(sql)?;
                existing.insert((lid, v.visit_time), (vid, v.rank()));
                stats.visits_updated += 1;
                if let Some(ft) = v.from_visit_time {
                    to_link.push((vid, v.visit_time, ft));
                }
            }
            continue;
        }
        con.execute(
            "INSERT INTO visits (url, visit_time, from_visit, transition, segment_id, visit_duration) VALUES (?1,?2,0,?3,0,?4)",
            (lid, v.visit_time, v.transition, v.visit_duration),
        )
        .map_err(sql)?;
        let vid = con.last_insert_rowid();
        existing.insert((lid, v.visit_time), (vid, v.rank()));
        stats.visits_inserted += 1;
        if let Some(ft) = v.from_visit_time {
            to_link.push((vid, v.visit_time, ft));
        }
    }
    for (vid, _, ft) in to_link {
        let found: Option<i64> = con
            .query_row(
                "SELECT v.id FROM visits v LEFT JOIN urls u ON u.id = v.url \
                 WHERE v.visit_time=?1 AND v.id != ?2 ORDER BY u.url, v.id LIMIT 1",
                (ft, vid),
                |r| r.get(0),
            )
            .optional()
            .map_err(sql)?;
        match found {
            Some(id) => {
                con.execute("UPDATE visits SET from_visit=?1 WHERE id=?2", (id, vid)).map_err(sql)?;
            }
            None => stats.from_visit_zeroed += 1,
        }
    }

    // visit_count and last_visit_time are recomputed from the rows that are actually there.
    let mut seen = HashSet::new();
    for lid in touched {
        if !seen.insert(lid) {
            continue;
        }
        let (count, newest): (i64, Option<i64>) = con
            .query_row("SELECT COUNT(*), MAX(visit_time) FROM visits WHERE url=?1", [lid], |r| Ok((r.get(0)?, r.get(1)?)))
            .map_err(sql)?;
        let last = merged_last.get(&lid).copied().unwrap_or(0).max(newest.unwrap_or(0));
        con.execute("UPDATE urls SET visit_count=?1, last_visit_time=?2 WHERE id=?3", (count, last, lid))
            .map_err(sql)?;
    }
    Ok(stats)
}

/// Merge `section` into the History at `path` in one transaction. `Ok(None)` when the profile
/// has no History yet (the browser creates it later). A locked database (browser open) is
/// `Error::BrowserOpen` and nothing changes. The caller's journal (txn.rs) owns backups.
pub fn import(path: &Path, section: &Section) -> Result<Option<Stats>> {
    if !path.exists() {
        return Ok(None);
    }
    let mut con = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_WRITE).map_err(sql)?;
    con.busy_timeout(std::time::Duration::from_secs(5)).map_err(sql)?;
    let tx = con.transaction_with_behavior(TransactionBehavior::Immediate).map_err(sql)?;
    let stats = merge(&tx, section)?;
    tx.commit().map_err(sql)?;
    Ok(Some(stats))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SHARED: &str = "https://shared.example.com/";
    const A_ONLY: &str = "https://a-only.example.com/";
    const B_ONLY: &str = "https://b-only.example.com/";
    const T1: i64 = 13350000100000000;
    const T2: i64 = 13350000200000000;
    const T3: i64 = 13350000300000000;
    const T4: i64 = 13350000400000000;
    const T5: i64 = 13350000500000000;

    const SCHEMA: &str = "
    CREATE TABLE meta (key LONGVARCHAR NOT NULL UNIQUE PRIMARY KEY, value LONGVARCHAR);
    INSERT INTO meta (key, value) VALUES ('version', '22');
    CREATE TABLE urls (
        id INTEGER PRIMARY KEY AUTOINCREMENT, url LONGVARCHAR, title LONGVARCHAR,
        visit_count INTEGER DEFAULT 0 NOT NULL, typed_count INTEGER DEFAULT 0 NOT NULL,
        last_visit_time INTEGER NOT NULL, hidden INTEGER DEFAULT 0 NOT NULL);
    CREATE TABLE visits (
        id INTEGER PRIMARY KEY AUTOINCREMENT, url INTEGER NOT NULL REFERENCES urls(id),
        visit_time INTEGER NOT NULL, from_visit INTEGER DEFAULT 0 NOT NULL,
        transition INTEGER DEFAULT 0 NOT NULL, segment_id INTEGER,
        visit_duration INTEGER DEFAULT 0 NOT NULL,
        incremented_omnibox_typed_score BOOLEAN DEFAULT FALSE NOT NULL,
        publicly_routable BOOLEAN DEFAULT FALSE NOT NULL,
        visit_source INTEGER DEFAULT 0 NOT NULL, browser_type INTEGER NOT NULL DEFAULT 0);
    CREATE INDEX visits_url_index ON visits (url);
    CREATE INDEX visits_time_index ON visits (visit_time);
    CREATE INDEX visits_from_index ON visits (from_visit);";

    /// (url, title, typed, hidden)
    type U = (&'static str, &'static str, i64, i64);
    /// (url, visit_time, parent: None | Some(Ok(time)) | Some(Err(())) dangling, transition, duration)
    type V = (&'static str, i64, Option<std::result::Result<i64, ()>>, i64, i64);

    /// Build a History DB the way the browser would have it: counts and last_visit_time consistent.
    fn make(path: &Path, urls: &[U], visits: &[V]) {
        let con = Connection::open(path).unwrap();
        con.execute_batch("PRAGMA foreign_keys=ON").unwrap();
        con.execute_batch(SCHEMA).unwrap();
        let mut ids = HashMap::new();
        for (url, title, typed, hidden) in urls {
            con.execute(
                "INSERT INTO urls (url, title, visit_count, typed_count, last_visit_time, hidden) VALUES (?1,?2,0,?3,0,?4)",
                (url, title, typed, hidden),
            )
            .unwrap();
            ids.insert(*url, con.last_insert_rowid());
        }
        let mut by_time = HashMap::new();
        for (url, t, parent, tr, dur) in visits {
            let from = match parent {
                None => 0,
                Some(Ok(pt)) => by_time[pt],
                Some(Err(())) => 987_654, // dangling: that visit was pruned away
            };
            con.execute(
                "INSERT INTO visits (url, visit_time, from_visit, transition, segment_id, visit_duration) VALUES (?1,?2,?3,?4,0,?5)",
                (ids[url], t, from, tr, dur),
            )
            .unwrap();
            by_time.insert(*t, con.last_insert_rowid());
        }
        con.execute_batch(
            "UPDATE urls SET visit_count=(SELECT COUNT(*) FROM visits WHERE visits.url=urls.id),
             last_visit_time=COALESCE((SELECT MAX(visit_time) FROM visits WHERE visits.url=urls.id),0)",
        )
        .unwrap();
    }

    fn a_db(p: &Path) {
        make(
            p,
            &[(SHARED, "Shared", 1, 0), (A_ONLY, "A Only", 2, 0)],
            &[(SHARED, T1, None, 0, 5000), (A_ONLY, T2, Some(Ok(T1)), 1, 3000), (SHARED, T4, Some(Ok(T1)), 1, 2000)],
        );
    }

    fn b_db(p: &Path) {
        make(
            p,
            &[(SHARED, "", 0, 0), (B_ONLY, "B Only", 3, 0)],
            &[(SHARED, T3, Some(Err(())), 1, 4000), (SHARED, T4, Some(Ok(T3)), 1, 2000), (B_ONLY, T5, Some(Ok(T3)), 1, 6000)],
        );
    }

    fn pair() -> (tempfile::TempDir, PathBuf, PathBuf) {
        let t = tempfile::tempdir().unwrap();
        let (a, b) = (t.path().join("A"), t.path().join("B"));
        a_db(&a);
        b_db(&b);
        (t, a, b)
    }

    /// Everything that must agree after a trade, as plain sorted data (row ids excluded, but the
    /// referrer is compared by its target's (url, time)).
    type Snapshot = (Vec<(String, String, i64, i64, i64, i64)>, Vec<(String, i64, Option<(String, i64)>, i64, i64)>);
    fn snapshot(p: &Path) -> Snapshot {
        let con = Connection::open(p).unwrap();
        let mut st = con
            .prepare("SELECT url, title, visit_count, typed_count, last_visit_time, hidden FROM urls ORDER BY url")
            .unwrap();
        let urls = st
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?)))
            .unwrap()
            .map(|r| r.unwrap())
            .collect();
        let mut st = con
            .prepare(
                "SELECT u.url, v.visit_time, fu.url, f.visit_time, v.transition, v.visit_duration \
                 FROM visits v JOIN urls u ON u.id=v.url \
                 LEFT JOIN visits f ON f.id=v.from_visit AND v.from_visit != 0 \
                 LEFT JOIN urls fu ON fu.id=f.url ORDER BY u.url, v.visit_time",
            )
            .unwrap();
        let visits = st
            .query_map([], |r| {
                let fu: Option<String> = r.get(2)?;
                let ft: Option<i64> = r.get(3)?;
                Ok((r.get(0)?, r.get(1)?, fu.zip(ft), r.get(4)?, r.get(5)?))
            })
            .unwrap()
            .map(|r| r.unwrap())
            .collect();
        (urls, visits)
    }

    #[test]
    fn export_reads_urls_and_visits_with_referrers_by_time() {
        let (_t, a, b) = pair();
        let s = export(&a).unwrap();
        assert_eq!(s.urls.len(), 2);
        assert_eq!(s.urls[0].url, A_ONLY);
        assert_eq!(s.visits.len(), 3);
        assert_eq!(s.visits[0].from_visit_time, None);
        assert_eq!(s.visits[1].from_visit_time, Some(T1));
        // B's first visit had a dangling referrer: exported as null.
        let sb = export(&b).unwrap();
        assert_eq!(sb.visits[0].from_visit_time, None);
        assert_eq!(sb.urls[1].title, "", "null/empty title exports as empty string");
        // No History file: empty section.
        assert_eq!(export(&a.with_file_name("none")).unwrap(), Section::default());
    }

    #[test]
    fn json_shape_matches_the_reference() {
        let v = Visit { url: "u".into(), visit_time: 5, from_visit_time: None, transition: 1, visit_duration: 2 };
        assert_eq!(
            serde_json::to_string(&v).unwrap(),
            r#"{"url":"u","visit_time":5,"from_visit_time":null,"transition":1,"visit_duration":2}"#
        );
        let s: Section = serde_json::from_str(r#"{"urls":[{"url":"u"}],"visits":[{"url":"u","visit_time":3}]}"#).unwrap();
        assert_eq!(s.urls[0].title, "");
        assert_eq!(s.visits[0].from_visit_time, None);
        let u = HistoryUrl { url: "u".into(), title: "t".into(), typed_count: 1, last_visit_time: 2, hidden: 0 };
        assert_eq!(
            serde_json::to_string(&u).unwrap(),
            r#"{"url":"u","title":"t","typed_count":1,"last_visit_time":2,"hidden":0}"#
        );
    }

    #[test]
    fn cross_import_converges_and_counts_are_real() {
        let (_t, a, b) = pair();
        let (ea, eb) = (export(&a).unwrap(), export(&b).unwrap());
        let sa = import(&a, &eb).unwrap().unwrap();
        let sb = import(&b, &ea).unwrap().unwrap();
        assert_eq!(snapshot(&a), snapshot(&b));
        let (urls, visits) = snapshot(&a);
        assert_eq!(urls.len(), 3);
        // Union of (url, time) pairs, no duplicates.
        let pairs: Vec<_> = visits.iter().map(|v| (v.0.as_str(), v.1)).collect();
        let mut want = vec![(SHARED, T1), (SHARED, T3), (SHARED, T4), (A_ONLY, T2), (B_ONLY, T5)];
        want.sort();
        assert_eq!(pairs, want);
        // visit_count equals row counts; last_visit_time is the max; the longer title filled in.
        let shared = urls.iter().find(|u| u.0 == SHARED).unwrap();
        assert_eq!((shared.1.as_str(), shared.2, shared.4), ("Shared", 3, T4));
        // Cross-URL referrer chains were remapped onto the parent imported in the same run.
        let b_only = visits.iter().find(|v| v.0 == B_ONLY).unwrap();
        assert_eq!(b_only.2, Some((SHARED.to_string(), T3)));
        let a_only = visits.iter().find(|v| v.0 == A_ONLY).unwrap();
        assert_eq!(a_only.2, Some((SHARED.to_string(), T1)));
        // SHARED@T4 is the same visit on both devices; duration and transition tie, so the
        // larger referrer time (T3 over T1) wins on both sides.
        let t4 = visits.iter().find(|v| v.1 == T4).unwrap();
        assert_eq!(t4.2, Some((SHARED.to_string(), T3)));
        assert_eq!((sa.visits_inserted, sa.visits_skipped), (2, 1));
        assert_eq!((sb.visits_inserted, sb.visits_skipped), (2, 1));
        // The dangling referrer on B's T3 visit stays unlinked; nothing was zeroed by the merge.
        assert_eq!(sa.from_visit_zeroed + sb.from_visit_zeroed, 0);
        // Clean foreign keys.
        let con = Connection::open(&a).unwrap();
        let bad: i64 = con.query_row("SELECT COUNT(*) FROM pragma_foreign_key_check", [], |r| r.get(0)).unwrap();
        assert_eq!(bad, 0);
    }

    #[test]
    fn importing_twice_changes_nothing() {
        let (_t, a, b) = pair();
        let eb = export(&b).unwrap();
        import(&a, &eb).unwrap();
        let once = snapshot(&a);
        let s = import(&a, &eb).unwrap().unwrap();
        assert_eq!(snapshot(&a), once);
        assert_eq!((s.urls_inserted, s.urls_updated, s.visits_inserted, s.visits_updated), (0, 0, 0, 0));
        assert_eq!(s.visits_skipped, 3);
    }

    #[test]
    fn unresolvable_referrer_is_zeroed_and_counted() {
        let t = tempfile::tempdir().unwrap();
        let p = t.path().join("H");
        make(&p, &[], &[]);
        let sec = Section {
            urls: vec![],
            visits: vec![Visit {
                url: SHARED.into(),
                visit_time: T3,
                from_visit_time: Some(T1),
                transition: 1,
                visit_duration: 0,
            }],
        };
        let s = import(&p, &sec).unwrap().unwrap();
        assert_eq!((s.visits_inserted, s.from_visit_zeroed), (1, 1));
        let con = Connection::open(&p).unwrap();
        let from: i64 = con.query_row("SELECT from_visit FROM visits", [], |r| r.get(0)).unwrap();
        assert_eq!(from, 0);
        // The URL was created from the visit alone.
        let (c, last): (i64, i64) =
            con.query_row("SELECT visit_count, last_visit_time FROM urls", [], |r| Ok((r.get(0)?, r.get(1)?))).unwrap();
        assert_eq!((c, last), (1, T3));
    }

    #[test]
    fn missing_history_db_is_none_and_not_created() {
        let t = tempfile::tempdir().unwrap();
        let p = t.path().join("History");
        assert_eq!(import(&p, &Section::default()).unwrap(), None);
        assert!(!p.exists());
    }

    #[test]
    fn locked_database_is_browser_open_and_changes_nothing() {
        let (_t, a, b) = pair();
        let before = snapshot(&a);
        let eb = export(&b).unwrap();
        let hold = Connection::open(&a).unwrap();
        hold.execute_batch("BEGIN EXCLUSIVE").unwrap();
        // Same steps as import() with a short wait, so the test does not sit for 5 seconds.
        let mut con = Connection::open_with_flags(&a, OpenFlags::SQLITE_OPEN_READ_WRITE).unwrap();
        con.busy_timeout(std::time::Duration::from_millis(50)).unwrap();
        let err = con.transaction_with_behavior(TransactionBehavior::Immediate).map_err(sql).map(|_| ()).unwrap_err();
        assert_eq!(err, Error::BrowserOpen);
        drop(con);
        hold.execute_batch("ROLLBACK").unwrap();
        drop(hold);
        assert_eq!(snapshot(&a), before);
        let _ = eb;
    }

    #[test]
    fn a_failed_merge_rolls_the_whole_store_back() {
        let (_t, a, _b) = pair();
        let before = snapshot(&a);
        {
            let con = Connection::open(&a).unwrap();
            con.execute_batch("CREATE UNIQUE INDEX one_visit_per_time ON visits (visit_time)").unwrap();
        }
        let before_idx = snapshot(&a);
        assert_eq!(before, before_idx);
        // Two incoming visits at the same time collide on the unique index mid-merge.
        let sec = Section {
            urls: vec![],
            visits: vec![
                Visit { url: "https://x/".into(), visit_time: 99, from_visit_time: None, transition: 0, visit_duration: 0 },
                Visit { url: "https://y/".into(), visit_time: 99, from_visit_time: None, transition: 0, visit_duration: 0 },
            ],
        };
        assert!(import(&a, &sec).is_err());
        assert_eq!(snapshot(&a), before, "the new urls and first visit were rolled back");
    }

    fn one_url_db(p: &Path, url: U, hidden_visits: &[V]) {
        make(p, &[url], hidden_visits);
    }

    #[test]
    fn title_and_hidden_rules_agree_from_both_directions() {
        let t = tempfile::tempdir().unwrap();
        let (a, b) = (t.path().join("A"), t.path().join("B"));
        one_url_db(&a, (SHARED, "Same", 5, 0), &[]);
        one_url_db(&b, (SHARED, "Sama", 2, 1), &[]); // equal length, "Same" > "Sama"
        let (ea, eb) = (export(&a).unwrap(), export(&b).unwrap());
        import(&a, &eb).unwrap();
        import(&b, &ea).unwrap();
        assert_eq!(snapshot(&a), snapshot(&b));
        let u = &snapshot(&a).0[0];
        assert_eq!((u.1.as_str(), u.3, u.5), ("Same", 5, 1), "tie by text, typed max, hidden max");
    }

    #[test]
    fn duplicate_visit_with_different_fields_converges_both_directions() {
        let t = tempfile::tempdir().unwrap();
        let (a, b) = (t.path().join("A"), t.path().join("B"));
        // Same visit (SHARED@T4) recorded differently on each device.
        make(&a, &[(SHARED, "S", 0, 0)], &[(SHARED, T1, None, 0, 10), (SHARED, T4, Some(Ok(T1)), 1, 2000)]);
        make(&b, &[(SHARED, "S", 0, 0)], &[(SHARED, T3, None, 0, 10), (SHARED, T4, Some(Ok(T3)), 1, 7000)]);
        let (ea, eb) = (export(&a).unwrap(), export(&b).unwrap());
        let sa = import(&a, &eb).unwrap().unwrap();
        let sb = import(&b, &ea).unwrap().unwrap();
        assert_eq!(snapshot(&a), snapshot(&b));
        let t4 = snapshot(&a).1.into_iter().find(|v| v.1 == T4).unwrap();
        assert_eq!((t4.4, t4.3), (7000, 1), "the longer duration wins on both sides");
        assert_eq!(t4.2, Some((SHARED.to_string(), T3)), "and brings its referrer with it");
        assert_eq!((sa.visits_updated, sb.visits_updated), (1, 0));
    }

    #[test]
    fn shared_referrer_time_resolves_the_same_way_both_directions() {
        // Two different URLs have a visit at the very same time; a child points at that time.
        let t = tempfile::tempdir().unwrap();
        let (a, b) = (t.path().join("A"), t.path().join("B"));
        make(&a, &[("https://b.example/", "B", 0, 0), ("https://c.example/", "C", 0, 0)],
             &[("https://b.example/", T1, None, 0, 1), ("https://c.example/", T1, None, 0, 1)]);
        make(&b, &[("https://z.example/", "Z", 0, 0)], &[("https://z.example/", T2, Some(Err(())), 0, 1)]);
        // Give B's child a referrer time that matches the shared time by exporting then editing.
        let ea = export(&a).unwrap();
        let mut eb = export(&b).unwrap();
        eb.visits[0].from_visit_time = Some(T1);
        import(&a, &eb).unwrap();
        // Order-insensitive: build the same union in the opposite order into a third db.
        let c = t.path().join("C");
        make(&c, &[("https://z.example/", "Z", 0, 0)], &[("https://z.example/", T2, None, 0, 1)]);
        import(&c, &ea).unwrap();
        import(&c, &eb).unwrap();
        let child = |p: &Path| snapshot(p).1.into_iter().find(|v| v.1 == T2).unwrap().2;
        assert_eq!(child(&a), Some(("https://b.example/".to_string(), T1)), "smallest url wins");
        assert_eq!(child(&a), child(&c));
    }
}
