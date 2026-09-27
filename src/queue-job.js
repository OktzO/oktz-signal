import { AsyncLocalStorage } from 'node:async_hooks';

// The keys of the jobs whose execution led to the code now running, innermost
// last. AsyncLocalStorage is what tells a callback that re-enters the queue from
// inside a job (its context carries that job's key) apart from ordinary
// concurrency (a different context, with the job merely still in flight) — to any
// plain "is a job running" flag the two look identical, and reading the second as
// re-entrant would silently drop real messages instead of queueing them.
const ctx = new AsyncLocalStorage();

export class QueueJob {
  constructor() {
    this.queues = new Map();
  }
  async add(key, fn) {
    // Self-reentrancy: fn is being called from inside a job already running this
    // key. Chaining it would wait on the tail promise that job is itself waiting
    // on, and the pair never settles — a permanent hang, no error and no timeout
    // (libsignal's queue_job.js has the same hole, and 116e095 opened it up to
    // SessionBuilder too). It is dropped and resolves instead: work issued from
    // inside a job cannot be serialised against that job, and every call site has
    // already written the record before a storage callback can re-enter, so the
    // issuing job's write is the one that stands.
    if (ctx.getStore()?.has(key)) return;
    let queue = this.queues.get(key);
    if (!queue) {
      queue = Promise.resolve();
    }
    const run = queue.then(() => this.run(key, fn), () => this.run(key, fn));
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
  // A fresh set per job: two jobs queued from the same context are siblings, so
  // they must not see each other's key.
  run(key, fn) {
    const chain = new Set(ctx.getStore());
    chain.add(key);
    return ctx.run(chain, fn);
  }
}
