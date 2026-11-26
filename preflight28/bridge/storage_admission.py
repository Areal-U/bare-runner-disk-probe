"""Admit R28 Artifact writes against a finite, owner-bound public-repository policy."""
import json
import os
import re
import signal
import sys
import time
from datetime import datetime
from pathlib import Path

POLICY = "github-public-standard-r28-v1"
REPO = "Areal-U/bare-runner-disk-probe"
REPO_ID = 1450926240
BASE = "/repos/" + REPO
MIB = 1024 ** 2
DAY = 86400
# The two per-slot keys/descriptor, outcome marker, seal and slot journal
# are each verified / bounded separately. This covers their overlapping ZIPs.
CONTROL_RESERVE = 2 * MIB
# The maximum archive plus framing/JSON/ZIP is larger than the terminal APK path.
MAX_RELAY_ZIP = 7 * 1024**3 // 2 + 20 * MIB
CACHE_FLOOR = 128 * MIB
AUDITED_CACHES = (11016400308, 11017220077, 11008758795, 10780907241, 10720237602)
JOURNAL_DAYS = 30
# Longest serial tail after either 350-minute worker: privacy recheck and result.
JOURNAL_TAIL = (85+7)*60


class StorageUnconfirmed(ValueError):
    """No authoritative policy or stable provider view permits a write."""


class StorageFull(ValueError):
    """The measured working set exceeds the owner-approved byte ceiling."""


def require(check, reason):
    if not check:
        raise StorageUnconfirmed(reason)


def integer(value, name):
    require(type(value) is int and 0 < value <= 2**53 - 1, "Invalid " + name)
    return value


def policy(ticket, ack):
    fields = ("storage_policy", "artifact_ceiling_bytes", "storage_valid_until")
    require(all(key in ticket and ticket[key] == ack.get(key) for key in fields),
            "Missing or conflicting owner/collector storage policy")
    require(ticket["storage_policy"] == POLICY, "Unrecognized Artifact billing basis")
    ceiling = integer(ticket["artifact_ceiling_bytes"], "repository Artifact storage ceiling")
    expiry = ticket["storage_valid_until"]
    require(isinstance(expiry, str) and expiry.endswith("Z"), "Missing Artifact policy expiration")
    return ceiling, int(datetime.fromisoformat(expiry[:-1]+"+00:00").timestamp())


def private_witness_policy(api, release, ticket, origin_created):
    """Read the original authenticated storage grant after a cache-only rescue.

    The caller has already verified the exact owner-issued original or replacement
    ticket from its immutable claim. The original grant was for this specific
    physical run. Eligibility for a *new* retained ZIP is checked at upload.
    """
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "control"))
    import registration

    created = registration.instant(origin_created)
    _, ack = registration.checked_ack(api, release, ticket, created, created)
    return policy(ticket, ack)


def config(env):
    def number(key):
        value = env.get(key, "")
        require(re.fullmatch("[1-9][0-9]{0,15}", value or ""), "Missing or invalid " + key)
        return integer(int(value), key)
    ceiling = number("R28_STORAGE_CEILING")
    if env.get("R28_RELAY_BYTE_CEILING"):
        ceiling = min(ceiling, number("R28_RELAY_BYTE_CEILING"))
    return ceiling, number("R28_STORAGE_UNTIL")


def lease_size(env):
    verify = env.get("R28_STORAGE_VERIFY_ONLY", "false")
    require(verify in ("true","false"), "Unknown slot storage operation")
    # A verification-only slot sends only its small verify-only outcome.
    return 16*1024 if verify == "true" else MAX_RELAY_ZIP


def draft_room(release, env, *, claim):
    # Checkpoint and terminal are mutually exclusive. The checkpoint's intent,
    # up to two parts and manifest can each leave one alternate-name starter
    # (8 total). The terminal's cipher and receipt can similarly occupy 4 slots;
    # its immutable private witness needs one more (5 total). The initial claim
    # and claim witness each use one canonical name without a starter retry.
    count = len(release["assets"])
    product_slots = 8 if lease_size(env) == MAX_RELAY_ZIP else 0
    extra = product_slots + (2 if claim else 0)
    require(count + extra <= 1000, "Insufficient private Release asset slots")


def public_host(repository, runner):
    require(repository.get("id") == REPO_ID and repository.get("full_name") == REPO
            and repository.get("private") is False and repository.get("fork") is False
            and repository.get("visibility") == "public" and runner == "github-hosted",
            "Public non-fork R28 repository and the fixed standard hosted runner are required")


# Different legal layouts provide independent page responses when a cached
# total_count lags expiry. Every accepted layout must be complete on its own.
ARTIFACT_PAGE_SIZES = (100, 99, 50, 20, 97, 89)
MAX_ARTIFACTS = 5000
INVENTORY_SECONDS = 60


def artifact_receipt(row):
    require(isinstance(row, dict), "Invalid Artifact inventory row")
    aid, size, expires = row.get("id"), row.get("size_in_bytes"), row.get("expires_at")
    integer(aid, "Artifact ID")
    require(type(size) is int and size >= 0 and type(row.get("expired")) is bool
            and isinstance(expires, str) and expires.endswith("Z") and isinstance(row.get("name"), str),
            f"Invalid Artifact size, expiration or name for ID {aid}")
    expiry = int(datetime.fromisoformat(expires[:-1]+"+00:00").timestamp())
    return aid, (size, expiry, row["expired"], row["name"])


def artifact_view(get, per_page, observed):
    rows = {}
    initial = None
    changed_total = False
    count_changes = []
    duplicate_ids = set()
    for page in range(1, MAX_ARTIFACTS // per_page + 2):
        data = get(f"{BASE}/actions/artifacts?per_page={per_page}&page={page}")
        require(isinstance(data, dict), "Invalid Artifact inventory response")
        total, batch = data.get("total_count"), data.get("artifacts")
        require(type(total) is int and 0 <= total <= MAX_ARTIFACTS and
                isinstance(batch, list) and len(batch) <= per_page,
                f"Invalid Artifact pagination at per_page={per_page} page={page}")
        if initial is None:
            initial = total
        changed_total |= initial != total
        if initial != total and len(count_changes) < 5:
            count_changes.append([page, total])
        for row in batch:
            aid, receipt = artifact_receipt(row)
            if aid in rows:
                duplicate_ids.add(aid)
            if aid in observed and observed[aid] != row:
                fields = sorted(key for key in observed[aid].keys() | row.keys() if
                                key not in observed[aid] or key not in row or observed[aid][key] != row[key])
                raise StorageUnconfirmed(f"Artifact inventory still settling: ID {aid} changed metadata "
                                         f"{fields[:6]} at per_page={per_page} page={page}")
            observed[aid] = row
            rows[aid] = receipt
        require(len(observed) <= MAX_ARTIFACTS, "Artifact observation exceeds the repository inventory bound")
        if len(batch) < per_page:
            complete = not changed_total and not duplicate_ids and len(rows) == total
            print("R28_ARTIFACT_VIEW " + json.dumps(dict(per_page=per_page, pages=page, first_total=initial,
                  last_total=total, unique=len(rows), last_page_rows=len(batch), count_changes=count_changes,
                  duplicates=sorted(duplicate_ids)[:5], complete=complete)), flush=True)
            return rows if complete else None
    raise StorageUnconfirmed(f"Artifact inventory did not terminate within the bound at per_page={per_page}")


def receipt_rows(get, *, run_id=None):
    observed = {}
    previous = None
    consecutive = False
    def expired(*_):
        raise StorageUnconfirmed(f"Artifact inventory deadline {INVENTORY_SECONDS}s reached with "
                                 f"{len(observed)} observed IDs")
    # The caller's shorter alarm remains in force. Bound even a blocked GET.
    old_timer = signal.getitimer(signal.ITIMER_REAL)
    install_alarm = not old_timer[0] or old_timer[0] > INVENTORY_SECONDS
    began = time.monotonic()
    if install_alarm:
        old_handler = signal.signal(signal.SIGALRM, expired)
        signal.setitimer(signal.ITIMER_REAL, INVENTORY_SECONDS)
    try:
        for per_page in ARTIFACT_PAGE_SIZES:
            if len(observed) > 100 and per_page < 80:
                continue  # Keep full scans of large repositories near 100 rows per request.
            rows = artifact_view(get, per_page, observed)
            if rows is None:
                consecutive = False
                continue
            if previous is not None and previous != rows:
                missing = previous.keys() - rows.keys()
                added = rows.keys() - previous.keys()
                # Two workers of our own run can finish a control upload while
                # reading. Count all its new rows and require a new full witness.
                other = []
                for aid in added:
                    source = observed[aid].get("workflow_run")
                    if (run_id is None or not isinstance(source, dict) or source.get("id") != run_id
                            or source.get("repository_id") != REPO_ID or source.get("head_repository_id") != REPO_ID):
                        other.append(aid)
                if missing or other or not added:
                    raise StorageUnconfirmed("Artifact inventory still settling between complete layouts: "
                                             f"differing IDs, missing={sorted(missing)[:5]}, "
                                             f"unbound additions={sorted(other)[:5]}")
                print(f"Artifact inventory grew by {len(added)} bound rows from run {run_id}; "
                      "requiring another complete view", flush=True)
            elif previous is not None and consecutive:
                missing = observed.keys() - rows.keys()
                require(not missing, f"Complete Artifact layouts omit {len(missing)} previously observed "
                                     f"IDs: {sorted(missing)[:5]}")
                return rows
            previous = rows
            consecutive = True
        raise StorageUnconfirmed("Incomplete repository Artifact inventory: no two consecutive independent "
                                 f"complete layouts agreed ({len(observed)} distinct observed IDs)")
    finally:
        if install_alarm:
            signal.setitimer(signal.ITIMER_REAL, 0)
            signal.signal(signal.SIGALRM, old_handler)
            if old_timer[0]:
                remaining = max(0.000001, old_timer[0] - (time.monotonic() - began))
                signal.setitimer(signal.ITIMER_REAL, remaining, old_timer[1])


ACTIVE_STATES = ("in_progress", "queued", "waiting", "pending", "requested")


def active_listing(get, run):
    """Return the sole observed state of this run and any evidence of an incomplete listing."""
    present = []
    issues = []
    for state in ACTIVE_STATES:
        data = get(f"{BASE}/actions/runs?status={state}&per_page=2")
        count = data.get("total_count") if isinstance(data, dict) else None
        rows = data.get("workflow_runs") if isinstance(data, dict) else None
        count_label = str(count) if type(count) is int else "invalid"
        length = len(rows) if isinstance(rows, list) else "invalid"
        summary = f"state={state} count={count_label} rows={length}"
        if not isinstance(rows, list):
            issues.append(summary)
            continue
        ids = [row.get("id") if isinstance(row, dict) else None for row in rows]
        for rid in ids:
            if type(rid) is int and rid > 0 and rid != run:
                raise StorageUnconfirmed(f"Another run {rid} in {summary} (current {run})")
        if type(count) is not int or count != len(rows):
            issues.append(summary + " (total and returned rows disagree)")
        elif any(type(rid) is not int or rid != run for rid in ids):
            issues.append(summary + " (invalid run ID)")
        elif len(rows) > 1:
            issues.append(summary + f" (duplicate current run {run})")
        elif any(row.get("status", state) != state for row in rows):
            issues.append(summary + f" (current run {run} row status disagrees with filter)")
        elif ids:
            present.append(state)
    if len(present) > 1:
        issues.append(f"current run {run} appears in multiple states {present}")
    return tuple(present), issues


def check_active_runs(get, env):
    run = integer(int(env["GITHUB_RUN_ID"]), "current run ID")
    _, issues = active_listing(get, run)
    if not issues:
        return
    print("Active-run inventory needs recheck: " + "; ".join(issues), flush=True)

    # Only an inconsistent inventory gets two independent re-reads. Require the
    # two complete views to agree. A foreign ID or a failed read never permits a write.
    def expired(*_):
        raise StorageUnconfirmed("Active-run inventory recheck exceeded 30 seconds")
    require(not signal.getitimer(signal.ITIMER_REAL)[0], "Another deadline is active during run recheck")
    previous = signal.signal(signal.SIGALRM, expired)
    try:
        signal.setitimer(signal.ITIMER_REAL, 30)
        snapshots = []
        for _ in range(2):
            time.sleep(2)
            present, issues = active_listing(get, run)
            require(not issues, "Active-run inventory recheck incomplete: " + "; ".join(issues))
            snapshots.append(present)
        require(snapshots[0] == snapshots[1], f"Active-run inventory rechecks differ: {snapshots}")
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)


def admit(get, env, size, days, *, stage, now=None, lead=0, exact_name=None):
    ceiling, until = config(env)
    live_clock = now is None
    started = time.monotonic()
    initial_time = time.time() if live_clock else now
    now = int(initial_time)
    integer(size, "incoming ZIP bytes")
    require(days in (1,3,JOURNAL_DAYS) and lead in (0,350*60), "Unrecognized Artifact lifetime")
    guarantee_days = max(days, JOURNAL_DAYS) if stage == "lease" else days
    # Include the remaining upload step(s) after the fresh gate. The slot
    # journal rechecks its own timestamp immediately before its 7-minute job ends.
    dispatch_margin = {"lease":JOURNAL_TAIL, "peer":6*60, "control":10*60, "terminal":10*60, "witness":10*60, "outcome":7*60}[stage]
    require(until >= now + lead + dispatch_margin + guarantee_days * DAY, "Storage policy expires before retained bytes")
    public_host(get(BASE), env.get("RUNNER_ENVIRONMENT"))
    # Every normal workflow uses ubuntu-24.04 literally. All numbered slots
    # serialize under a single campaign; count ALL listed Artifacts including
    # expired rows still exposed by GitHub. Do not spend today's space in
    # anticipation of an expiry or assume a second run's unfinished upload is 0.
    check_active_runs(get, env)
    rows = receipt_rows(get, run_id=int(env["GITHUB_RUN_ID"]))
    # Inventory recovery can cross an eligibility boundary while reading. Check
    # competing runs and the owner's retention grant again at the write decision.
    check_active_runs(get, env)
    now = int(time.time() if live_clock else initial_time + (time.monotonic() - started))
    require(until >= now + lead + dispatch_margin + guarantee_days * DAY,
            "Storage policy expired during the Artifact inventory check")
    visible = sum(row[0] for row in rows.values())
    expiring = sum(row[0] for row in rows.values() if row[2] or row[1] <= now)
    projected = visible + size + CONTROL_RESERVE
    print("R28_ARTIFACT_ADMISSION "+json.dumps(dict(stage=stage, policy=POLICY, ceiling_bytes=ceiling,
          known_repository_bytes=visible, expired_still_visible_bytes=expiring, candidate_zip_ceiling_bytes=size,
          concurrent_control_bytes=CONTROL_RESERVE, peak_bytes=projected, retention_days=days,
          projected_expiry_epoch=now+lead+days*DAY, control_retention_days=JOURNAL_DAYS,
          latest_retained_expiry_epoch=now+lead+dispatch_margin+guarantee_days*DAY, policy_until=until,
          earliest_unexpired_epoch=min((r[1] for r in rows.values() if not r[2] and r[1]>now),default=None),
          capped_gib_hours=(size*days*24)/(1024**3)),sort_keys=True),flush=True)
    if exact_name and any(row[3]==exact_name for row in rows.values()):
        return "existing"
    if projected > ceiling:
        raise StorageFull("Candidate exceeds configured repository Artifact storage ceiling")
    return "admitted"


def admit_witness(get, env, file, *, now=None):
    require(file.name == "witness.json" and file.is_file() and not file.is_symlink() and
            0 < file.stat().st_size <= 8*1024, "Invalid or oversized owner witness")
    # One stored ZIP member; the receiver independently enforces the same outer
    # and inner limits. A denied witness does not invalidate a private deposit.
    return admit(get, env, 16*1024, JOURNAL_DAYS, stage="witness", now=now)


def cache_fallback(get, env, encrypted):
    require(type(encrypted) is int and 0 < encrypted <= 451*MIB, "Invalid sealed APK cache size")
    public_host(get(BASE), env.get("RUNNER_ENVIRONMENT"))
    check_active_runs(get, env)
    limit_gib = integer(get(BASE+"/actions/cache/storage-limit")["max_cache_size_gb"], "service cache limit")
    # A concurrent writer can arrive after inventory. A service-enforced free
    # ceiling prevents a bill even in that race, without changing account policy.
    require(limit_gib <= 10, "The live cache service limit permits paid capacity")
    ceiling = limit_gib * 1024**3

    def inventory():
        # This build's five old generations occupy almost all of the free
        # allocation. An unknown or changing inventory cannot justify eviction.
        listed = get(BASE+"/actions/caches?per_page=100&page=1")
        entries = listed["actions_caches"]
        require(isinstance(entries, list) and len(entries) <= 100 and type(listed["total_count"]) is int
                and len(entries) == listed["total_count"], "Incomplete cache inventory")
        by_id = {}
        for entry in entries:
            cid = integer(entry["id"], "cache id")
            amount = entry["size_in_bytes"]
            require(cid not in by_id and type(amount) is int and amount >= 0
                    and all(isinstance(entry[k],str) and entry[k] for k in ("key","ref","version")),
                    "Ambiguous cache inventory")
            by_id[cid] = (amount, entry["key"], entry["ref"], entry["version"])
        return by_id

    rows = inventory()
    usage = get(BASE + "/actions/cache/usage")["active_caches_size_in_bytes"]
    require(type(usage) is int and usage >= 0 and rows == inventory(), "Cache inventory is still settling")
    occupied = max(usage, sum(row[0] for row in rows.values()))
    peak = occupied + encrypted + 2*MIB + CACHE_FLOOR
    print("R28_APK_CACHE_ADMISSION "+json.dumps(dict(occupied=occupied, ceiling=ceiling, encrypted=encrypted,
          archive_overhead=2*MIB, unallocated=CACHE_FLOOR, peak=peak, retained_audit_ids=[k for k in AUDITED_CACHES if k in rows]),
          sort_keys=True),flush=True)
    if peak > ceiling:
        raise StorageFull("Sealed APK would displace existing cache bytes or exceed the free cache ceiling")
    return peak


def main():
    import argparse
    import bridge
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("stage", choices=("terminal","lease","control","cache","peer","witness"))
    parser.add_argument("--terminal-bytes", type=int)
    parser.add_argument("--file", type=Path, action="append")
    args = parser.parse_args()
    if args.stage == "witness":
        require(args.file is not None and len(args.file) == 1, "One owner witness file required")
        admit_witness(bridge.api_json, os.environ, args.file[0])
        return
    if args.stage == "cache":
        cache_fallback(bridge.api_json, os.environ, args.terminal_bytes)
        return
    if args.stage == "terminal":
        require(args.terminal_bytes is not None and 0 < args.terminal_bytes <= 451*MIB,
                "Invalid sealed APK size")
        size, days, lead = args.terminal_bytes+2*MIB, 3, 0
    elif args.stage == "peer":
        require(bool(args.file) and len(args.file) <= 2 and
                all(p.is_file() and not p.is_symlink() for p in args.file), "Invalid peer files")
        size, days, lead = sum(p.stat().st_size for p in args.file) + 8*1024, 1, 0
        require(size <= 256*1024, "Oversized peer control Artifact")
    elif args.stage == "lease":
        size, days, lead = lease_size(os.environ), 1, 350*60
    else:
        size, days, lead = 16*1024, JOURNAL_DAYS, 0
    admit(bridge.api_json, os.environ, size, days, stage=args.stage, lead=lead)


if __name__ == "__main__":
    main()
