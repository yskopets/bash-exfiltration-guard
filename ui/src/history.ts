import type { Verdict } from './api'

/** How many commands to keep. Oldest fall off the end. */
export const LIMIT = 100

const KEY = 'guard.history.v1'

export type HistoryEntry = {
  command: string
  verdict: Verdict
  at: number
}

/**
 * remember puts an entry at the front and caps the list at LIMIT.
 *
 * Re-assessing a command moves it to the front rather than adding a second
 * copy. A history full of the same command you clicked six times is a worse
 * record of what you have looked at than one line saying you looked at it.
 *
 * Pure, so the capping and the de-duplication can be reasoned about without a
 * browser.
 */
export function remember(list: HistoryEntry[], entry: HistoryEntry): HistoryEntry[] {
  const rest = list.filter((e) => e.command !== entry.command)
  return [entry, ...rest].slice(0, LIMIT)
}

/**
 * load reads the stored history.
 *
 * Anything unreadable is treated as empty: this is a convenience, and a
 * corrupt value should not take the page down with it.
 */
export function load(): HistoryEntry[] {
  try {
    const raw = localStorage.getItem(KEY)
    if (!raw) return []
    const parsed: unknown = JSON.parse(raw)
    if (!Array.isArray(parsed)) return []
    return parsed
      .filter(
        (e): e is HistoryEntry =>
          typeof e === 'object' &&
          e !== null &&
          typeof (e as HistoryEntry).command === 'string' &&
          typeof (e as HistoryEntry).verdict === 'string',
      )
      .slice(0, LIMIT)
  } catch {
    return []
  }
}

/** save persists the history, ignoring a storage that refuses to be written. */
export function save(list: HistoryEntry[]): void {
  try {
    localStorage.setItem(KEY, JSON.stringify(list))
  } catch {
    // Private browsing, a full quota, or storage disabled. The page works
    // without it; the history is just forgotten on reload.
  }
}
