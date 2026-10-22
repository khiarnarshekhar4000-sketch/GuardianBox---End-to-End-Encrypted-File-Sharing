import cron from 'node-cron';

/** Delete every expired or exhausted file from storage first, then from the DB. */
export async function cleanupExpired(db, storage, now = Date.now()) {
  const ids = db.findDeadIds(now);
  let removed = 0;
  for (const id of ids) {
    try {
      await storage.remove(id);
      db.delete(id);
      removed++;
    } catch (err) {
      console.error(`[cleanup] failed to remove ${id}:`, err.message);
    }
  }
  return removed;
}

/** Runs at minute 0 of every hour, plus once at startup. */
export function startCleanupJob(db, storage) {
  const run = () =>
    cleanupExpired(db, storage)
      .then((n) => n && console.log(`[cleanup] removed ${n} file(s)`))
      .catch((e) => console.error('[cleanup] error', e));
  run();
  return cron.schedule('0 * * * *', run);
}
