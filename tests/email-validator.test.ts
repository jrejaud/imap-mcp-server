import { describe, it, expect } from 'vitest';
import net from 'net';
import { checkSyntax, checkMx, probeSmtp, validateEmail } from '../src/services/email-validator.js';

describe('checkSyntax', () => {
  it('accepts ordinary addresses', () => {
    for (const addr of ['jordan@alastor.space', 'a.b+tag@sub.example.co.uk', "o'brien@example.com"]) {
      expect(checkSyntax(addr).verdict, addr).toBe('valid');
    }
  });

  it('rejects malformed addresses without any network call', () => {
    const cases = ['', 'no-at-sign', 'two@@example.com', '@example.com', 'user@', 'user@nodot', 'a..b@example.com', 'user@-bad.com'];
    for (const addr of cases) {
      expect(checkSyntax(addr).verdict, addr).toBe('invalid');
    }
  });

  it('enforces RFC length limits', () => {
    expect(checkSyntax(`${'a'.repeat(65)}@example.com`).verdict).toBe('invalid');
    expect(checkSyntax(`${'a'.repeat(250)}@example.com`).reason).toMatch(/254/);
  });

  it('lowercases the domain and splits on the last @', () => {
    expect(checkSyntax('User@Example.COM')).toMatchObject({ verdict: 'valid', localPart: 'User', domain: 'example.com' });
  });
});

describe('checkMx', () => {
  it('finds MX hosts for a real mail domain, sorted by priority', async () => {
    const result = await checkMx('gmail.com');
    expect(result.verdict).toBe('valid');
    expect(result.hosts.length).toBeGreaterThan(0);
    const priorities = result.hosts.map(h => h.priority);
    expect([...priorities].sort((a, b) => a - b)).toEqual(priorities);
  });

  it('calls a non-resolving domain invalid — no mail route exists', async () => {
    const result = await checkMx('this-domain-does-not-exist-4f2a9c.invalid');
    expect(result.verdict).toBe('invalid');
    expect(result.source).toBe('none');
  });

  it('returns unknown rather than invalid when DNS is too slow to answer', async () => {
    const result = await checkMx('gmail.com', 1);
    expect(result.verdict).toBe('unknown');
  });
});

describe('probeSmtp', () => {
  // A fake MX so the RCPT paths are exercised without touching a real server.
  async function withFakeMx(handler: (line: string) => string | null, fn: (port: number) => Promise<void>) {
    const server = net.createServer(socket => {
      socket.setEncoding('utf8');
      socket.write('220 fake.mx ESMTP\r\n');
      socket.on('data', chunk => {
        for (const line of chunk.split(/\r?\n/).filter(Boolean)) {
          if (/^QUIT/i.test(line)) {
            socket.write('221 Bye\r\n');
            socket.end();
            return;
          }
          const reply = handler(line);
          if (reply) socket.write(reply + '\r\n');
        }
      });
      socket.on('error', () => {});
    });
    await new Promise<void>(res => server.listen(0, '127.0.0.1', res));
    const { port } = server.address() as net.AddressInfo;
    try {
      await fn(port);
    } finally {
      await new Promise<void>(res => server.close(() => res()));
    }
  }

  const opts = (port: number) => ({ timeoutMs: 3000, helo: 'test.local', mailFrom: '', port });

  it('returns valid when the real address is accepted and a random control is rejected', async () => {
    await withFakeMx(
      line => {
        if (/^EHLO/i.test(line)) return '250 ok';
        if (/^MAIL FROM/i.test(line)) return '250 ok';
        if (/^RCPT TO:<real@fake\.test>/i.test(line)) return '250 Accepted';
        if (/^RCPT TO/i.test(line)) return '550 No such user';
        return '250 ok';
      },
      async port => {
        const r = await probeSmtp('127.0.0.1', 'real@fake.test', 'fake.test', opts(port));
        expect(r).toMatchObject({ verdict: 'valid', code: 250, catchAll: false });
      },
    );
  });

  it('returns invalid on a 550 rejection of the recipient', async () => {
    await withFakeMx(
      line => (/^RCPT TO/i.test(line) ? '550 5.1.1 User unknown' : '250 ok'),
      async port => {
        const r = await probeSmtp('127.0.0.1', 'ghost@fake.test', 'fake.test', opts(port));
        expect(r).toMatchObject({ verdict: 'invalid', code: 550 });
      },
    );
  });

  it('returns unknown — not valid — when the server accepts every recipient (catch-all)', async () => {
    await withFakeMx(
      () => '250 ok',
      async port => {
        const r = await probeSmtp('127.0.0.1', 'anything@fake.test', 'fake.test', opts(port));
        expect(r).toMatchObject({ verdict: 'unknown', catchAll: true });
        expect(r.reason).toMatch(/catch-all/);
      },
    );
  });

  it('returns unknown — not invalid — on a 4xx greylist deferral', async () => {
    await withFakeMx(
      line => (/^RCPT TO/i.test(line) ? '450 4.7.1 Greylisted, try again later' : '250 ok'),
      async port => {
        const r = await probeSmtp('127.0.0.1', 'grey@fake.test', 'fake.test', opts(port));
        expect(r).toMatchObject({ verdict: 'unknown', code: 450 });
      },
    );
  });

  it('returns unknown when the server blocks our client at EHLO', async () => {
    await withFakeMx(
      line => (/^EHLO|^HELO/i.test(line) ? '554 5.7.1 Client host blocked' : '250 ok'),
      async port => {
        const r = await probeSmtp('127.0.0.1', 'user@fake.test', 'fake.test', opts(port));
        expect(r.verdict).toBe('unknown');
        expect(r.stage).toBe('ehlo');
      },
    );
  });

  it('treats an unreachable MX as unknown, and honours the timeout', async () => {
    const r = await probeSmtp('127.0.0.1', 'user@fake.test', 'fake.test', { timeoutMs: 1500, helo: 'test.local', mailFrom: '', port: 9 });
    expect(r.verdict).toBe('unknown');
    expect(r.durationMs).toBeLessThan(5000);
  });
});

describe('validateEmail', () => {
  it('short-circuits on bad syntax without a DNS lookup', async () => {
    const r = await validateEmail('not-an-email');
    expect(r.verdict).toBe('invalid');
    expect(r.checks.mx).toBeUndefined();
  });

  it('is invalid when the domain has no mail route', async () => {
    const r = await validateEmail('someone@this-domain-does-not-exist-4f2a9c.invalid');
    expect(r.verdict).toBe('invalid');
    expect(r.checks.mx?.source).toBe('none');
  });

  // Live SMTP is deliberately NOT exercised here: probing a real MX from CI would
  // trip abuse detection, and most networks block outbound 25 anyway. The RCPT
  // state machine is covered against the fake MX above.
  it('stops at unknown for a routable domain when --smtp is off', async () => {
    const r = await validateEmail('jordan@alastor.space');
    expect(r.verdict).toBe('unknown');
    expect(r.checks.mx?.verdict).toBe('valid');
    expect(r.checks.smtp).toBeUndefined();
  });
});
