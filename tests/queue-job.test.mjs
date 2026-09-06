import { describe, it } from 'node:test';
import assert from 'node:assert';
import { QueueJob } from '../src/queue-job.js';

const drain = () => new Promise((r) => setTimeout(r, 0));

describe('QueueJob cleanup', () => {
  it('serial jalan berurutan same key (sequential)', async () => {
    const q = new QueueJob();
    const order = [];
    await q.add('k', async () => { order.push(1); });
    await q.add('k', async () => { order.push(2); });
    assert.deepStrictEqual(order, [1, 2]);
  });

  it('serial tetap walau add concurrent same key', async () => {
    const q = new QueueJob();
    const order = [];
    const running = [];
    for (let i = 1; i <= 5; i++) {
      running.push(q.add('k', async () => {
        order.push(`start-${i}`);
        await new Promise((r) => setTimeout(r, 5));
        order.push(`end-${i}`);
      }));
    }
    await Promise.all(running);
    // tidak ada job interleaving
    for (let i = 0; i < 5; i++) {
      assert.strictEqual(order[i * 2], `start-${i + 1}`);
      assert.strictEqual(order[i * 2 + 1], `end-${i + 1}`);
    }
  });

  it('map entry dihapus setelah settle', async () => {
    const q = new QueueJob();
    await q.add('k', async () => {});
    await drain();
    assert.strictEqual(q.queues.size, 0);
  });

  it('entry tidak dihapus premature saat follower ada (concurrent)', async () => {
    const q = new QueueJob();
    const p1 = q.add('k', async () => { await new Promise((r) => setTimeout(r, 10)); });
    const p2 = q.add('k', async () => {});
    await p1; // p1 settle, tapi p2 masih tail → entry tetap
    assert.strictEqual(q.queues.size, 1);
    await p2;
    await drain();
    assert.strictEqual(q.queues.size, 0);
  });

  it('rejection tidak bocor unhandled dan entry tetap dibersihkan', async () => {
    const q = new QueueJob();
    const boom = q.add('k', async () => { throw new Error('x'); });
    await assert.rejects(boom, /x/);
    const ok = q.add('k', async () => 'v');
    await ok; // fn sebelumnya reject → chain lanjut via (fn, fn)
    assert.strictEqual(await ok, 'v');
    await drain();
    assert.strictEqual(q.queues.size, 0);
  });
});
