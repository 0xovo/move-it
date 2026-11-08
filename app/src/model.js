export const countLabels = { logins: 'logins and cookies', passwords: 'saved passwords', extensions: 'extensions', bookmarks: 'bookmarks', history: 'history items' };
export function totals(browsers) {
  return Object.fromEntries(Object.keys(countLabels).map(k => [k, browsers.reduce((n, b) => n + (Number(b[k]) || 0), 0)]));
}
export function reportLines(report) {
  const lines = [`${report.cookies || 0} cookies received`, `${report.logins || 0} passwords received`, `${report.historyUrls || 0} history items received`];
  if (report.wroteBox) lines.push('Your sealed box is ready in the shared folder. Run Move It on the other device to receive it.');
  for (const route of report.routes || []) lines.push(route.status === 'moved' ? `${route.profile} → ${route.toBrowser}: ${route.intoProfile || 'received'}` : `${route.profile}: ${route.reason || 'could not move'}`);
  return lines;
}
