// Public configuration. The PUBLISHABLE key is designed to be public: Row Level
// Security makes the database read-only for it (verified: INSERT → permission denied).
// Never place the secret / service_role key in frontend code.
export const SUPABASE_URL = 'https://ckdsqjrlfffpdsuuwwby.supabase.co';
export const SUPABASE_PUBLISHABLE_KEY = 'sb_publishable_diaMU1eKINnKFgFw_BfSeg_j6ur7epy';

// Content-change tracking (migration 002) went live on this date. Before it,
// the app has no evidence about whether CERT-In revised a note.
export const TRACKING_SINCE = '2026-10-21';

// A refresh older than this many hours shows a stale-data warning.
export const STALE_AFTER_HOURS = 30;
