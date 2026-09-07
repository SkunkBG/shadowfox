#!/bin/sh
# Хеши на странице входа сверяются с эталонными векторами и со
# случайными строками против crypto из node. Это протокол роутера
# (MD5 внутри SHA-256), и своя реализация обязана совпадать байт в байт
# с тем, что считает служба в digest.c. Без node — пропуск с пометкой.
set -eu
ROOT=$(cd "$(dirname "$0")/.." && pwd)

command -v node >/dev/null 2>&1 || { echo "check-login-js: нет node, пропуск"; exit 0; }

node - "$ROOT/web/login.js" <<'JS'
const fs=require('fs'), crypto=require('crypto');
const src=fs.readFileSync(process.argv[2],'utf8');
/* Берём только функции хешей, без обвязки формы: DOM здесь нет. */
const cut=src.indexOf('document.addEventListener');
eval(cut>0?src.slice(0,cut):src);
let bad=0;
const eq=(a,b,w)=>{ if(a!==b){ console.log('  ПРОВАЛ', w, a, b); bad++; } };
eq(md5(''),'d41d8cd98f00b204e9800998ecf8427e','md5 пусто');
eq(md5('abc'),'900150983cd24fb0d6963f7d28e17f72','md5 abc');
eq(sha256('abc'),'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad','sha abc');
for(let i=0;i<200;i++){
  const len=Math.floor(Math.random()*200); let s='';
  for(let k=0;k<len;k++) s+=String.fromCharCode(Math.random()<0.3?0x410+Math.floor(Math.random()*64):32+Math.floor(Math.random()*90));
  const b=Buffer.from(s,'utf8');
  eq(md5(s),crypto.createHash('md5').update(b).digest('hex'),'md5 #'+i);
  eq(sha256(s),crypto.createHash('sha256').update(b).digest('hex'),'sha #'+i);
}
console.log(bad?'ПРОВАЛЕНО проверок: '+bad:'check-login-js: все проверки пройдены');
process.exit(bad?1:0);
JS
