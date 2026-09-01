export class QueueJob {
  constructor() {
    this.queues = new Map();
  }
  async add(key, fn) {
    let queue = this.queues.get(key);
    if (!queue) {
      queue = Promise.resolve();
      this.queues.set(key, queue);
    }
    queue = queue.then(fn, fn);
    this.queues.set(key, queue);
    return queue;
  }
}