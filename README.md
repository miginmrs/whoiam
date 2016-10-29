# Whoiam
This script is a timestamp based non-interactive identity proof that tells you who I am if you have the required information (for security purpose :D).

Unless the reuse is immediate, the provided proof is considered zero knowledge.
# Use
If you have an anonymous account and you want to prove your identity to someone without giving him the possibility to reuse this proof later you can use this script.

This can't help if the user may reuse the proof immediately.

This is made for users you don't have credentials. In the other case, you can use an interactive proof or a pairing based proof.
# The script
## Creation of keys
```javascript
(function(window) {
  'use strict';
  var crypto = window.crypto ? window.crypto : window.msCrypto;
  var subtle = crypto.subtle;
  subtle.generateKey({name:'RSASSA-PKCS1-v1_5', hash:{name:'sha-256'}, modulusLength:2048, publicExponent: new Uint8Array([1,0,1])}, true, ['sign', 'verify']).then(function(key){
    return Promise.all([
      subtle.exportKey('jwk', key.publicKey),
      subtle.exportKey('jwk', key.privateKey)
    ]);
  }).then(function(keys){
    console.log("var publicKey = "+JSON.stringify(keys[0])+";\n\nvar privateKey = "+JSON.stringify(keys[1]));
  });
})(window)
```
## Creation of credentials
```javascript
(function(window) {
  'use strict';
  var crypto = window.crypto ? window.crypto : window.msCrypto;
  var subtle = crypto.subtle;
  function btoab(b) {
    var buf = new ArrayBuffer(b.length);
    var bufView = new Uint8Array(buf);
    for (var i=0, strLen=b.length; i<strLen; i++) {
      bufView[i] = b.charCodeAt(i);
    }
    return buf;
  }
  function abtob(buf) {
    return String.fromCharCode.apply(null, new Uint8Array(buf));
  }
  function atou(a) {
    return a.replace(/\//g, '_').replace(/\+/g, '-').replace(/=/g, '');
  }
  window.credentials = function(name, privateKey, date, delay, code, url) {
    var time = Math.floor(date.getTime()/1000)+'-'+delay;
    var keyPromise = subtle.importKey('jwk', {kty: 'oct', k:atou(btoa(code)), alg: 'A128CBC', ext: false}, {name:'AES-CBC', length:128}, false, ['encrypt']);
    var signaturePromise = subtle.importKey('jwk', privateKey, {name:'RSASSA-PKCS1-v1_5', hash:{name:'sha-256'}}, false, ['sign']).then(function(key){
      return subtle.sign('RSASSA-PKCS1-v1_5', key, btoab(time));
    }).then(abtob);
    var iv = new Uint8Array(16);
    crypto.getRandomValues(iv);
    Promise.all([keyPromise, signaturePromise]).then(function(data) {
      return subtle.encrypt({name:'AES-CBC', iv:iv}, data[0], btoab(time+':'+btoa(name)+':'+data[1]))
    }).then(function(data){console.log(url+'#'+atou(btoa(abtob(iv)+abtob(data))));});
  }
})(window)
// import privateKey: 
// var privateKey = ...
// then
// credentials(name, privateKey, date, delay, code, url)
```
## Use of credentials
```javascript
(function(window){
  'use strict';
  var crypto = window.crypto ? window.crypto : window.msCrypto;
  var subtle = crypto.subtle;
  function abtob(buf) {
    return String.fromCharCode.apply(null, new Uint8Array(buf));
  }
  function btoab(b) {
    var buf = new ArrayBuffer(b.length);
    var bufView = new Uint8Array(buf);
    for (var i=0, strLen=b.length; i<strLen; i++) {
      bufView[i] = b.charCodeAt(i);
    }
    return buf;
  }
  function atou(a) {
    return a.replace(/\//g, '_').replace(/\+/g, '-').replace(/=/g, '');
  }
  var verify_id = function(b64udata, code, date, publicKey) {
    var keypromise = subtle.importKey('jwk', publicKey, {name:'RSASSA-PKCS1-v1_5', hash:{name:'sha-256'}}, false, ['verify']);
    while (b64udata.length % 4) b64udata += '=';
    var encdata = atob(b64udata.replace(/_/g, '/').replace(/-/g, '+'));
    var datapromise = subtle.importKey('jwk', {kty: 'oct', k:atou(btoa(code)), alg: 'A128CBC', ext: false}, {name:'AES-CBC', length:128}, false, ['decrypt']).then(
      key=>subtle.decrypt({name:'AES-CBC', iv:btoab(encdata.slice(0,16))}, key, btoab(encdata.slice(16)))
    ).then(abtob);
    return Promise.all([keypromise, datapromise]).then(t=>{
      var key = t[0];
      var data = t[1];
      var namepos = data.indexOf(':');
      var encpos = data.indexOf(':', namepos+1);
      var datatime = data.slice(0, namepos);
      var name = atob(data.slice(namepos+1, encpos));
      var dataenc = data.slice(encpos+1);
      var times = datatime.split('-');
      var ctime = parseInt(times[0]);
      var delay = parseInt(times[1]);
      return crypto.subtle.verify({name:'RSASSA-PKCS1-v1_5', hash:{name:'sha-256'}},
        key, btoab(dataenc), btoab(datatime)
      ).then(result=>{
        var now = Math.floor(date.getTime()/1000);
        if(!result) console.log('Failed user identification as : '+name);
        else if(now<ctime+delay) console.log('I am '+name);
        else console.log('Enable to verify user identity due to a late reception of '+(now-ctime)+' seconds giving a chance to a man in the middle to decrypt, change the name to '+name+' then reencrypt and resend');
      });
    })
  };
  window.verify = function(code, reception_time) {
    verify_id(location.hash.slice(1), code, new Date(reception_time), window.publicKey).then(console.log)
  }
})(window);
// Place here the publicKey definition
// var publicKey = ...
// Please set the received credentials as :
// verify(code, reception_time)
```
# Example
If I have sent you a link to my github profile associated with my credentials, you can just use the received information when running the script under the current page inspector, and it will confirm or not the given identity.

Otherwise you can use this [link](https://github.com/miginmrs/whoiam#KSxbHTqTAWUR17Zjs4tR2ZeP3ZSLmvAhH_p4lIvfg4jgVSVKaU7-oNa7tS5mm8ribcG52wMDlQ_aGHBSy0DFfzvbX9mm994EDJt1U_k4bqO-ZYPg8IkOlEklwUMBhvnQ60odCqWELNePVoBJNa500mXPlDi4KFtNErynRDnnlEAl_UzV9_fgcK17bQq676V5uhG0ClEjZzr30kBm854RUPuI5p180tgQ0YoR1JPygdsxtvHlr_uD1MrXdREZuznwpmhKT7SpfWKpAJn5uYKKw9ggDjK-JR0HFiphnhV4mwFYr86-oKG0kgWmEfksz6sRrzEjME6Z9DYF3AbOIKEdCY5oWnkcYS6sP8Z6UnwTc2Dck7PlqI5VrGQAdrM08tZFIzHM81hwNPJDASDt4TgwEFKY_yDZi604Op9nkM7VxY7_ZRMLZR0hWwQ-y1asLYRr) where the used code is '0123456789abcdef' and the received date is new Date('2016-10-29 19:00:10Z') 
```javascript
var publicKey = {alg:"RS256",e:"AQAB",ext:true,key_ops:["verify"],kty:"RSA",n:"0_Pw4YoF0CUF7HzDS8_CtfKNhujMkkeCnB6ZPsOv9eqh6pScPmXyF_ctB5TbbmDuSTKvXE1-fTO1BElTVn6ZMZWt_K9xno98EpJRRCgw9uuPpYxR1NIRNpYIq3KKb3UQ8SlU-j_f5kegHRfDQla5_xJtd1ztXYFOS7dzkLWTWBsbwUk3zWX5DCp8zqiw66hI67oBGCpNwk4sMv1B861XlApDyc3CKfe71Of4-gD97X97ORI8PBP9q4AXksdNIIUWNRthh5Xmd2yZJ5ZlxSgI0veoYO2shqef1hQnFvcv_KWc5dJ5OsfPjBC-6PLEYobcdbHOnAyzAwN3_9AkwvTTWw"};
// Please set the received credentials as verify(code, reception_time), example:
// verify('0123456789abcdef', new Date('2016-10-29 19:00:10Z'))
```
