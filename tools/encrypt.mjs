#!/usr/bin/env node
/*
  Шифрует медданные + PDF в vault.json (AES-256-GCM, ключ из пароля через PBKDF2).
  Пароль вводится скрыто и НИКУДА не сохраняется. Запуск:

      node tools/encrypt.mjs

  Читает:  plaintext/vault-source.json  +  analyses/NN.pdf
  Пишет:   vault.json   (это единственный файл с данными, который уходит в репозиторий)

  Параметры криптографии совпадают с теми, что использует браузер в index.html.
*/
import { readFileSync, writeFileSync, existsSync, readdirSync } from 'node:fs';
import { pbkdf2Sync, randomBytes, createCipheriv } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import readline from 'node:readline';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const ITER = 250000;            // итерации PBKDF2 (должно совпадать с браузером)
const SRC  = join(ROOT, 'plaintext', 'vault-source.json');
const PDIR = join(ROOT, 'analyses');
const OUT  = join(ROOT, 'vault.json');

function askHidden(q) {
  if (process.env.PASSPHRASE) return Promise.resolve(process.env.PASSPHRASE); // для авто-теста
  return new Promise((resolve) => {
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
    const out = process.stdout;
    let first = true;
    rl._writeToOutput = (s) => { if (first) { out.write(s); first = false; } }; // печатаем только сам вопрос
    rl.question(q, (a) => { rl.close(); out.write('\n'); resolve(a); });
  });
}

const b64 = (buf) => Buffer.from(buf).toString('base64');

(async () => {
  if (!existsSync(SRC)) { console.error('Нет файла ' + SRC); process.exit(1); }

  const data = JSON.parse(readFileSync(SRC, 'utf8'));

  // подмешиваем PDF как base64
  data.pdfs = {};
  let n = 0;
  if (existsSync(PDIR)) {
    for (const f of readdirSync(PDIR).filter((f) => f.endsWith('.pdf')).sort()) {
      const key = f.replace(/\.pdf$/, '');
      data.pdfs[key] = readFileSync(join(PDIR, f)).toString('base64');
      n++;
    }
  }

  const pass1 = await askHidden('Придумай пароль для трекера (введи, символы не показываются): ');
  if (!pass1 || pass1.length < 4) { console.error('Слишком короткий пароль. Минимум 4 символа.'); process.exit(1); }
  const pass2 = await askHidden('Повтори пароль: ');
  if (pass1 !== pass2) { console.error('Пароли не совпали. Ничего не изменено.'); process.exit(1); }

  const salt = randomBytes(16);
  const iv   = randomBytes(12);
  const key  = pbkdf2Sync(Buffer.from(pass1, 'utf8'), salt, ITER, 32, 'sha256');

  const plain  = Buffer.from(JSON.stringify(data), 'utf8');
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  const enc    = Buffer.concat([cipher.update(plain), cipher.final()]);
  const tag    = cipher.getAuthTag();
  const ct     = Buffer.concat([enc, tag]); // формат WebCrypto: шифртекст + тег

  writeFileSync(OUT, JSON.stringify({
    v: 1,
    kdf: { salt: b64(salt), iter: ITER, hash: 'SHA-256' },
    iv: b64(iv),
    ct: b64(ct)
  }));

  console.log('\n✅ Готово: vault.json (' + (ct.length / 1024 / 1024).toFixed(2) + ' МБ), зашифровано анализов: ' + n + ' PDF.');
  console.log('   Пароль нигде не сохранён. Не забудь его — восстановить нельзя, только пересобрать заново.');
})();
