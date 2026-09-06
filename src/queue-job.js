export class QueueJob {
  constructor() {
    this.queues = new Map();
  }
  async add(key, fn) {
    let queue = this.queues.get(key);
    if (!queue) {
      queue = Promise.resolve();
    }
    const run = queue.then(fn, fn);
    this.queues.set(key, run);
    run.catch(() => {}); // avoid unhandled rejection dari chain tersimpan
    // kalau masih tail saat settle → tak ada follower → hapus entry.
    // kalau add() lain replace entry sebelum settle, identitas beda → biarkan.
    if (this.queues.get(key) === run) {
      const cleanup = () => { if (this.queues.get(key) === run) this.queues.delete(key); };
      run.then(cleanup, cleanup);
    }
    return run;
  }
}