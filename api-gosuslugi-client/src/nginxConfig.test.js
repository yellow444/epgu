import fs from 'fs';
import path from 'path';

describe('production nginx security policy', () => {
  const config = fs.readFileSync(
    path.resolve(__dirname, '../default.conf.template'),
    'utf8'
  );

  test('prevents framing by other sites and restricts executable content', () => {
    // 'self', а не 'none': приложение само показывает PDF из письма в рамке.
    // Чужой сайт встроить нас по-прежнему не может.
    expect(config).toContain("frame-ancestors 'self'");
    expect(config).toContain("script-src 'self'");
    expect(config).toContain("connect-src 'self'");
    expect(config).toContain('add_header X-Frame-Options "SAMEORIGIN" always;');
    expect(config).not.toContain('add_header X-Frame-Options "DENY" always;');
  });

  test('sets browser MIME and referrer protections on every response', () => {
    expect(config).toContain(
      'add_header X-Content-Type-Options "nosniff" always;'
    );
    expect(config).toContain('add_header Referrer-Policy "no-referrer" always;');
  });

  test('allows the 50 MB backend aggregate limit plus multipart overhead', () => {
    expect(config).toContain('client_max_body_size 64m;');
    expect(config).not.toContain('client_max_body_size 512m;');
  });
});
