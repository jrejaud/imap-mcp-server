import { promises as dns } from 'dns';
import net from 'net';
import os from 'os';
import crypto from 'crypto';

export type Verdict = 'valid' | 'invalid' | 'unknown';

export interface SyntaxCheck {
  verdict: Verdict;
  reason?: string;
  localPart?: string;
  domain?: string;
}

export interface MxHost {
  exchange: string;
  priority: number;
}

export interface MxCheck {
  verdict: Verdict;
  reason?: string;
  source: 'mx' | 'implicit-a' | 'none';
  hosts: MxHost[];
}

export interface SmtpCheck {
  verdict: Verdict;
  reason?: string;
  host?: string;
  stage?: 'connect' | 'greeting' | 'ehlo' | 'mail-from' | 'rcpt-to' | 'catch-all';
  code?: number;
  response?: string;
  catchAll?: boolean;
  durationMs?: number;
}

export interface ValidationResult {
  address: string;
  verdict: Verdict;
  reason: string;
  checks: {
    syntax: SyntaxCheck;
    mx?: MxCheck;
    smtp?: SmtpCheck;
  };
}

export interface ValidateOptions {
  smtp?: boolean;
  timeoutMs?: number;
  helo?: string;
  mailFrom?: string;
  port?: number;
}

// RFC 5321 dot-atom local-part + LDH domain labels. Deliberately rejects the
// quoted-string form (`"a b"@x.com`) — legal but effectively nonexistent as a
// real recipient, and accepting it costs more false negatives than it saves.
const ADDRESS_RE =
  /^[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+)*@(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$/;

export function checkSyntax(address: string): SyntaxCheck {
  const value = (address ?? '').trim();
  if (!value) return { verdict: 'invalid', reason: 'empty address' };
  if (value.length > 254) return { verdict: 'invalid', reason: `address exceeds 254 chars (${value.length})` };

  const at = value.lastIndexOf('@');
  if (at <= 0 || at === value.length - 1) {
    return { verdict: 'invalid', reason: 'missing local-part or domain around "@"' };
  }
  const localPart = value.slice(0, at);
  const domain = value.slice(at + 1).toLowerCase();

  if (localPart.length > 64) {
    return { verdict: 'invalid', reason: `local-part exceeds 64 chars (${localPart.length})`, localPart, domain };
  }
  if (!ADDRESS_RE.test(value)) {
    return { verdict: 'invalid', reason: 'does not match RFC 5321 dot-atom address shape', localPart, domain };
  }
  return { verdict: 'valid', localPart, domain };
}

function withTimeout<T>(promise: Promise<T>, ms: number, onTimeout: () => T): Promise<T> {
  return new Promise(resolve => {
    let settled = false;
    const timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      resolve(onTimeout());
    }, ms);
    promise.then(
      value => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        resolve(value);
      },
      () => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        resolve(onTimeout());
      },
    );
  });
}

export async function checkMx(domain: string, timeoutMs = 5000): Promise<MxCheck> {
  const timedOut = (): MxCheck => ({ verdict: 'unknown', reason: `DNS lookup timed out after ${timeoutMs}ms`, source: 'none', hosts: [] });

  return withTimeout(
    (async (): Promise<MxCheck> => {
      let records: MxHost[] = [];
      try {
        records = await dns.resolveMx(domain);
      } catch (err: any) {
        if (err?.code !== 'ENODATA' && err?.code !== 'ENOTFOUND') {
          return { verdict: 'unknown', reason: `MX lookup failed: ${err?.code || err?.message}`, source: 'none', hosts: [] };
        }
      }

      // RFC 7505 null MX — the domain explicitly declares it accepts no mail.
      if (records.length === 1 && (records[0].exchange === '' || records[0].exchange === '.')) {
        return { verdict: 'invalid', reason: 'domain publishes a null MX (RFC 7505) — it accepts no mail', source: 'mx', hosts: [] };
      }

      if (records.length > 0) {
        const hosts = [...records].sort((a, b) => a.priority - b.priority);
        return { verdict: 'valid', source: 'mx', hosts };
      }

      // No MX: RFC 5321 §5.1 says fall back to the domain's A/AAAA record.
      const addresses = await Promise.allSettled([dns.resolve4(domain), dns.resolve6(domain)]);
      const resolved = addresses.some(r => r.status === 'fulfilled' && r.value.length > 0);
      if (resolved) {
        return { verdict: 'valid', reason: 'no MX record; falling back to implicit MX (A/AAAA)', source: 'implicit-a', hosts: [{ exchange: domain, priority: 0 }] };
      }
      return { verdict: 'invalid', reason: 'domain has no MX record and does not resolve — no mail route exists', source: 'none', hosts: [] };
    })(),
    timeoutMs,
    timedOut,
  );
}

interface SmtpSession {
  send(line: string): Promise<{ code: number; text: string }>;
  close(): void;
}

function openSmtpSession(host: string, port: number, timeoutMs: number): Promise<{ session: SmtpSession; greeting: { code: number; text: string } }> {
  return new Promise((resolve, reject) => {
    const socket = net.createConnection({ host, port });
    socket.setEncoding('utf8');
    socket.setTimeout(timeoutMs);

    let buffer = '';
    let pending: { resolve: (r: { code: number; text: string }) => void; reject: (e: Error) => void } | null = null;
    let settledOpen = false;

    const finishReply = () => {
      // A reply is complete once a line is "NNN " (space, not hyphen).
      const lines = buffer.split(/\r?\n/);
      for (let i = 0; i < lines.length; i++) {
        if (/^\d{3} /.test(lines[i])) {
          const text = lines.slice(0, i + 1).join('\n');
          buffer = lines.slice(i + 1).join('\n');
          return { code: Number(lines[i].slice(0, 3)), text };
        }
      }
      return null;
    };

    const drain = () => {
      const reply = finishReply();
      if (!reply) return;
      if (!settledOpen) {
        settledOpen = true;
        resolve({ session, greeting: reply });
        return;
      }
      const p = pending;
      pending = null;
      p?.resolve(reply);
    };

    const abort = (err: Error) => {
      socket.destroy();
      if (!settledOpen) {
        settledOpen = true;
        reject(err);
        return;
      }
      const p = pending;
      pending = null;
      p?.reject(err);
    };

    socket.on('data', chunk => {
      buffer += chunk;
      drain();
    });
    socket.on('timeout', () => abort(new Error(`SMTP timeout after ${timeoutMs}ms`)));
    socket.on('error', err => abort(err as Error));
    socket.on('close', () => abort(new Error('SMTP connection closed by peer')));

    const session: SmtpSession = {
      send(line: string) {
        return new Promise((res, rej) => {
          pending = { resolve: res, reject: rej };
          socket.write(line + '\r\n');
        });
      },
      close() {
        socket.destroy();
      },
    };
  });
}

export async function probeSmtp(
  host: string,
  address: string,
  domain: string,
  opts: { timeoutMs: number; helo: string; mailFrom: string; port: number },
): Promise<SmtpCheck> {
  const started = Date.now();
  const elapsed = () => Date.now() - started;
  let session: SmtpSession | undefined;
  let stage: SmtpCheck['stage'] = 'connect';

  try {
    const opened = await openSmtpSession(host, opts.port, opts.timeoutMs);
    session = opened.session;

    stage = 'greeting';
    if (opened.greeting.code !== 220) {
      return { verdict: 'unknown', reason: 'server did not greet with 220', host, stage, code: opened.greeting.code, response: opened.greeting.text, durationMs: elapsed() };
    }

    stage = 'ehlo';
    let hello = await session.send(`EHLO ${opts.helo}`);
    if (hello.code >= 400) hello = await session.send(`HELO ${opts.helo}`);
    if (hello.code >= 400) {
      return { verdict: 'unknown', reason: 'server rejected our EHLO/HELO — it is refusing this client, not the address', host, stage, code: hello.code, response: hello.text, durationMs: elapsed() };
    }

    stage = 'mail-from';
    const mailFrom = await session.send(`MAIL FROM:<${opts.mailFrom}>`);
    if (mailFrom.code >= 400) {
      return { verdict: 'unknown', reason: 'server rejected our MAIL FROM — it is refusing this client, not the address', host, stage, code: mailFrom.code, response: mailFrom.text, durationMs: elapsed() };
    }

    stage = 'rcpt-to';
    const rcpt = await session.send(`RCPT TO:<${address}>`);

    if (rcpt.code === 250 || rcpt.code === 251) {
      stage = 'catch-all';
      const control = `${crypto.randomBytes(12).toString('hex')}@${domain}`;
      const decoy = await session.send(`RCPT TO:<${control}>`);
      const catchAll = decoy.code === 250 || decoy.code === 251;
      await session.send('QUIT').catch(() => {});
      if (catchAll) {
        return {
          verdict: 'unknown',
          reason: 'catch-all domain — the server accepts every recipient, so a 250 proves nothing about this mailbox',
          host, stage, code: rcpt.code, response: rcpt.text, catchAll: true, durationMs: elapsed(),
        };
      }
      return { verdict: 'valid', reason: 'server accepted RCPT TO for this address and rejected a random control address', host, stage: 'rcpt-to', code: rcpt.code, response: rcpt.text, catchAll: false, durationMs: elapsed() };
    }

    await session.send('QUIT').catch(() => {});

    if (rcpt.code >= 500) {
      return { verdict: 'invalid', reason: 'server rejected the recipient outright', host, stage, code: rcpt.code, response: rcpt.text, durationMs: elapsed() };
    }
    return { verdict: 'unknown', reason: 'server deferred the recipient (greylisting or rate limit)', host, stage, code: rcpt.code, response: rcpt.text, durationMs: elapsed() };
  } catch (err: any) {
    return { verdict: 'unknown', reason: `SMTP probe did not complete: ${err?.message || String(err)}`, host, stage, durationMs: elapsed() };
  } finally {
    session?.close();
  }
}

export async function validateEmail(address: string, opts: ValidateOptions = {}): Promise<ValidationResult> {
  const timeoutMs = opts.timeoutMs ?? 5000;
  const trimmed = (address ?? '').trim();

  const syntax = checkSyntax(trimmed);
  if (syntax.verdict !== 'valid') {
    return { address: trimmed, verdict: 'invalid', reason: syntax.reason!, checks: { syntax } };
  }

  const mx = await checkMx(syntax.domain!, timeoutMs);
  if (mx.verdict === 'invalid') {
    return { address: trimmed, verdict: 'invalid', reason: mx.reason!, checks: { syntax, mx } };
  }
  if (mx.verdict === 'unknown') {
    return { address: trimmed, verdict: 'unknown', reason: mx.reason!, checks: { syntax, mx } };
  }

  if (!opts.smtp) {
    return {
      address: trimmed,
      verdict: 'unknown',
      reason: 'syntax is well-formed and the domain has a mail route; mailbox existence not probed (pass --smtp to try)',
      checks: { syntax, mx },
    };
  }

  const smtp = await probeSmtp(mx.hosts[0].exchange, trimmed, syntax.domain!, {
    timeoutMs,
    helo: opts.helo || os.hostname(),
    mailFrom: opts.mailFrom ?? '',
    port: opts.port ?? 25,
  });

  return { address: trimmed, verdict: smtp.verdict, reason: smtp.reason!, checks: { syntax, mx, smtp } };
}
