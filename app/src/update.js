/** @typedef {{ pendingVersion: string | null, dismissedVersion: string | null, engineIdle: boolean, onMoveScreen: boolean, uiBusy: boolean }} UpdateGate */

export const GITHUB_RELEASE = 'https://github.com/0xovo/move-it/releases/latest';

export function updateNoticeText(version) {
  return `Move It ${version} is ready`;
}

export function updatePrimaryLabel(packageManaged) {
  return packageManaged ? 'Get it on GitHub' : 'Update now';
}

/** @param {UpdateGate} gate */
export function shouldShowUpdateNotice(gate) {
  if (!gate.pendingVersion) return false;
  if (gate.pendingVersion === gate.dismissedVersion) return false;
  if (!gate.engineIdle || gate.onMoveScreen || gate.uiBusy) return false;
  return true;
}

/** @param {UpdateGate} gate */
export function shouldDeferUpdatePrompt(gate) {
  return !gate.engineIdle || gate.onMoveScreen || gate.uiBusy;
}
