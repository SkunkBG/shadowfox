/* MD5 (RFC 1321) и SHA-256 (FIPS 180-4) для страницы входа.
   Не наш выбор алгоритмов: это схема входа Keenetic —
     md5    = MD5(логин ":" realm ":" пароль)
     answer = SHA256(challenge + hex(md5))
   crypto.subtle на http-странице недоступен, поэтому вручную.
   Вход — строка, кодируется в UTF-8 как на стороне службы. */
function utf8(s){ return unescape(encodeURIComponent(s)); }
function hex(bytes){ return bytes.map(b=>('0'+(b&255).toString(16)).slice(-2)).join(''); }

function md5(str){
  const s=utf8(str); const n=s.length;
  const words=[]; for(let i=0;i<n;i++) words[i>>2]|=s.charCodeAt(i)<<((i%4)*8);
  words[n>>2]|=0x80<<((n%4)*8); words[(((n+8)>>6)<<4)+14]=n*8;
  const K=[]; for(let i=0;i<64;i++) K[i]=Math.floor(Math.abs(Math.sin(i+1))*4294967296)|0;
  const S=[7,12,17,22,7,12,17,22,7,12,17,22,7,12,17,22,5,9,14,20,5,9,14,20,5,9,14,20,5,9,14,20,
           4,11,16,23,4,11,16,23,4,11,16,23,4,11,16,23,6,10,15,21,6,10,15,21,6,10,15,21,6,10,15,21];
  let a0=0x67452301,b0=0xefcdab89,c0=0x98badcfe,d0=0x10325476;
  const rot=(x,c)=>(x<<c)|(x>>>(32-c));
  for(let i=0;i<words.length;i+=16){
    let a=a0,b=b0,c=c0,d=d0;
    for(let j=0;j<64;j++){
      let f,g;
      if(j<16){f=(b&c)|(~b&d);g=j;}
      else if(j<32){f=(d&b)|(~d&c);g=(5*j+1)%16;}
      else if(j<48){f=b^c^d;g=(3*j+5)%16;}
      else{f=c^(b|~d);g=(7*j)%16;}
      const t=d; d=c; c=b;
      b=(b+rot((a+f+K[j]+(words[i+g]|0))|0,S[j]))|0; a=t;
    }
    a0=(a0+a)|0;b0=(b0+b)|0;c0=(c0+c)|0;d0=(d0+d)|0;
  }
  const out=[]; for(const w of [a0,b0,c0,d0]) for(let k=0;k<4;k++) out.push((w>>>(k*8))&255);
  return hex(out);
}

function sha256(str){
  const s=utf8(str); const n=s.length;
  const K=[0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2];
  let H=[0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19];
  const words=[]; for(let i=0;i<n;i++) words[i>>2]|=s.charCodeAt(i)<<(24-(i%4)*8);
  words[n>>2]|=0x80<<(24-(n%4)*8);
  const total=(((n+8)>>6)<<4)+16; for(let i=words.length;i<total;i++) words[i]=0;
  words[total-1]=(n*8)>>>0; words[total-2]=Math.floor(n*8/4294967296);
  const rotr=(x,c)=>(x>>>c)|(x<<(32-c));
  const W=new Array(64);
  for(let i=0;i<total;i+=16){
    for(let t=0;t<16;t++) W[t]=words[i+t]|0;
    for(let t=16;t<64;t++){
      const s0=rotr(W[t-15],7)^rotr(W[t-15],18)^(W[t-15]>>>3);
      const s1=rotr(W[t-2],17)^rotr(W[t-2],19)^(W[t-2]>>>10);
      W[t]=(W[t-16]+s0+W[t-7]+s1)|0;
    }
    let [a,b,c,d,e,f,g,h]=H;
    for(let t=0;t<64;t++){
      const S1=rotr(e,6)^rotr(e,11)^rotr(e,25);
      const ch=(e&f)^(~e&g);
      const t1=(h+S1+ch+K[t]+W[t])|0;
      const S0=rotr(a,2)^rotr(a,13)^rotr(a,22);
      const maj=(a&b)^(a&c)^(b&c);
      const t2=(S0+maj)|0;
      h=g;g=f;f=e;e=(d+t1)|0;d=c;c=b;b=a;a=(t1+t2)|0;
    }
    H=[(H[0]+a)|0,(H[1]+b)|0,(H[2]+c)|0,(H[3]+d)|0,(H[4]+e)|0,(H[5]+f)|0,(H[6]+g)|0,(H[7]+h)|0];
  }
  const out=[]; for(const w of H) for(let k=3;k>=0;k--) out.push((w>>>(k*8))&255);
  return hex(out);
}

/* Форма входа. Пароль не покидает браузер: у службы берётся realm и
   challenge роутера, ответ считается здесь, и только он уходит на
   /login. Раньше пароль администратора шёл в открытом POST по LAN —
   сам роутер так никогда не делает. */
document.addEventListener('DOMContentLoaded', function(){
  var form=document.querySelector('form');
  if(!form) return;
  var msg=document.getElementById('msg');
  function say(t){ if(msg){ msg.textContent=t; msg.hidden=!t; } }

  form.addEventListener('submit', function(ev){
    ev.preventDefault();
    var login=form.login.value.trim(), pass=form.password.value;
    if(!login){ say('Введи логин'); return; }
    say('проверяю…');
    var btn=form.querySelector('button'); if(btn) btn.disabled=true;

    fetch('/auth',{cache:'no-store'}).then(function(r){ return r.json(); }).then(function(a){
      if(!a || !a.ok){ throw new Error(a && a.why ? a.why : 'служба не ответила'); }
      var answer=sha256(a.challenge+md5(login+':'+a.realm+':'+pass));
      pass='';
      var body='login='+encodeURIComponent(login)+'&answer='+answer+
               '&nonce='+encodeURIComponent(a.nonce);
      return fetch('/login',{method:'POST',
        headers:{'Content-Type':'application/x-www-form-urlencoded'},
        body:body});
    }).then(function(r){
      if(!r.ok) return r.text().then(function(t){ throw new Error(t.trim()||'вход отклонён'); });
      /* Метка сессии — в хранилище нашего origin, не в cookie: cookie
         браузер отдаёт всем службам на адресе роутера без разбора порта. */
      return r.json().then(function(j){
        if(!j || !j.session) throw new Error('служба не выдала сессию');
        try{ localStorage.setItem('sf-session', j.session); }catch(e){}
        location.href='/';
      });
    }).catch(function(e){
      say(e.message); if(btn) btn.disabled=false;
    });
  });
});
