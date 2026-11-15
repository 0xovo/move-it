export const kindDefs = [
  { id: 'passwords', label: 'Saved passwords', keys: ['logins', 'passwords'] },
  { id: 'cookies', label: 'Logins', detail: 'Stay signed in (cookies)' },
  { id: 'bookmarks', label: 'Bookmarks' },
  { id: 'history', label: 'History' },
  { id: 'extensions', label: 'Extensions' },
];

export function kindSummaryText(selectedCount, total = kindDefs.length) {
  if (selectedCount >= total) return 'All data';
  return `${selectedCount} of ${total} kinds`;
}

export function aggregateKinds(rows) {
  const out = {};
  for (const def of kindDefs) {
    if (def.keys) {
      out[def.id] = def.keys.reduce((n, k) => n + (Number(rows[k]) || 0), 0);
    } else {
      out[def.id] = Number(rows[def.id]) || 0;
    }
  }
  return out;
}

export function reportLines(report, { local = false, otherDevice = 'your other computer' } = {}) {
  const lines = [];
  const n = v => Number(v || 0).toLocaleString();
  const plural = (v, one, many) => `${n(v)} ${Number(v || 0) === 1 ? one : many}`;
  if (local) {
    lines.push(`${plural(report.logins, 'saved password', 'saved passwords')} moved`);
    lines.push(`${plural(report.historyUrls, 'history item', 'history items')} moved`);
    lines.push(`${plural(report.cookies, 'website login', 'website logins')} moved`);
    return lines;
  }
  if (report.sentProfiles) {
    lines.push(`Sent ${plural(report.sentProfiles, 'profile', 'profiles')}: ${plural(report.sentLogins, 'saved password', 'saved passwords')}, ${plural(report.sentHistoryUrls, 'history item', 'history items')}, ${plural(report.sentCookies, 'website login', 'website logins')}`);
  }
  const received = Number(report.cookies || 0) + Number(report.logins || 0) + Number(report.historyUrls || 0);
  if (received || report.boxesRead) {
    lines.push(`Received: ${plural(report.logins, 'saved password', 'saved passwords')}, ${plural(report.historyUrls, 'history item', 'history items')}, ${plural(report.cookies, 'website login', 'website logins')}`);
  }
  if (!report.sentProfiles && !received && !(report.routes || []).length) lines.push('Nothing new to move.');
  for (const line of report.routes || []) {
    if (line.status === 'moved') {
      const where = line.intoProfile ? `${line.toBrowser} (${line.intoProfile})` : line.toBrowser;
      lines.push(`Profile from ${line.fromBrowser} moved into ${where}`);
    } else {
      lines.push(`Profile from ${line.fromBrowser} could not land: ${line.reason || 'unknown error'}`);
    }
  }
  return lines;
}

/** How a profile slot reads in a picker: "Profile 1 (0xovo)" when the person
 * named the profile something other than its folder name, else the folder name. */
export function slotLabel(slot, name) {
  const who = String(name || '').trim();
  return who && who !== slot ? `${slot} (${who})` : String(slot);
}

/** The title the counts screen shows for a same-device source profile. */
export function sourceProfileTitle(browserDisplay, slot, name) {
  return `${browserDisplay} / ${slotLabel(slot, name)}`;
}

/** The id the shell keys a same-device profile by; mirrors the core's local
 * kind id ("local:" + the slot, lowercased, spaces as dashes). */
export function localProfileId(slot) {
  return `local:${String(slot).toLowerCase().replaceAll(' ', '-')}`;
}

/** Whether a browser's profiles need an explicit pick before a move. */
export function needsProfilePick(profiles) {
  return Array.isArray(profiles) && profiles.length > 1;
}

/** The slot selected without asking: the only profile's slot, or null when
 * the browser holds several and the person has to choose. */
export function preselectedSlot(profiles) {
  return Array.isArray(profiles) && profiles.length === 1 ? profiles[0].slot : null;
}

const onWindows = () => typeof navigator !== 'undefined' && /Windows/i.test(navigator.userAgent);

/** Plain-language line for preview/done "Needs attention" (no App-Bound on Linux). */
export function formatAttentionLine(entry, { windows = onWindows() } = {}) {
  const reason = (typeof entry === 'string' ? entry : entry?.reason) || '';
  const browser = (typeof entry === 'object' && entry?.browser) ? entry.browser : '';
  const win = windows;

  const cookies = reason.match(/^(\d+)\s+App-Bound cookies$/i);
  if (cookies) {
    const n = cookies[1];
    if (win) return `${n} sign-in cookies are locked by ${browser || 'the browser'} on Windows and stay behind`;
    return `${n} sign-in cookies stay on this device`;
  }
  const logins = reason.match(/^(\d+)\s+saved logins are App-Bound/i);
  if (logins) {
    const n = logins[1];
    const b = browser || 'the browser';
    if (win) return `${n} logins are locked by ${b} on Windows and stay behind`;
    return `${n} saved passwords use a protected format and will stay behind`;
  }
  if (/Windows App-Bound protection/i.test(reason)) {
    const b = browser || reason.split(/\s/)[0] || 'The browser';
    if (win) return `${b} has some data locked on Windows and will stay behind`;
    return `${b} has some protected data that will stay on this device`;
  }
  if (/App-Bound/i.test(reason)) {
    return reason.replace(/\bApp-Bound\b/gi, 'protected').replace(/\bapp-bound\b/gi, 'protected');
  }
  return reason;
}

export function skipLines(report) {
  const lines = [];
  for (const entry of report.skipped || []) {
    const head = entry.browser ? `${entry.browser}: ` : '';
    lines.push(head + formatAttentionLine(entry));
  }
  if (report.boxesSkipped) {
    lines.push(`${Number(report.boxesSkipped).toLocaleString()} file${report.boxesSkipped === 1 ? '' : 's'} could not be read and ${report.boxesSkipped === 1 ? 'was' : 'were'} skipped`);
  }
  if (report.lockedCookies) {
    lines.push(`${Number(report.lockedCookies).toLocaleString()} protected cookies stayed on this device`);
  }
  return lines;
}
