/* PR0CESS_LIVE // SEAL
   Signs every live command so only someone who entered a real PIN can drive
   the overlays. The secret overlay key is never in this code:
     - decks get it from the database after a correct PIN (rpc ov_key)
     - overlays inside OBS get it from their own link (?k=...)
   An overlay that has a key in its link ignores anything unsigned, forged,
   or older than 2 minutes, and never accepts the same message twice.       */
(function(){
"use strict";
var WIN=120000;                       /* how old a message may be */
var keyHex="", keyP=null, seen={}, q=Promise.resolve(), cbs=[];
var hasCrypto=!!(window.crypto&&crypto.subtle&&window.TextEncoder);

function urlKey(){
  var m=location.search.match(/[?&]k=([0-9a-f]{32,128})(?:&|$)/i);
  return m?m[1].toLowerCase():"";
}
function bytes(hex){
  var b=new Uint8Array(hex.length/2);
  for(var i=0;i<b.length;i++) b[i]=parseInt(hex.substr(i*2,2),16);
  return b;
}
function hexOf(buf){
  var a=new Uint8Array(buf), s="";
  for(var i=0;i<a.length;i++) s+=("0"+a[i].toString(16)).slice(-2);
  return s;
}
function data(ev,t,n,j){ return new TextEncoder().encode(ev+"|"+t+"|"+n+"|"+j); }
function nonce(){
  var a=new Uint8Array(9); crypto.getRandomValues(a); return hexOf(a);
}
function prune(){
  var now=Date.now(), k;
  for(k in seen){ if(now-seen[k]>WIN*2) delete seen[k]; }
}
function setKey(hex){
  hex=(hex||"").toLowerCase();
  if(!/^[0-9a-f]{32,128}$/.test(hex)||!hasCrypto){ return; }
  keyHex=hex;
  keyP=crypto.subtle.importKey("raw",bytes(hex),{name:"HMAC",hash:"SHA-256"},false,["sign","verify"]);
  var l=cbs.slice(); l.forEach(function(f){ try{ f(keyHex); }catch(e){} });
}

var URLK=urlKey();
var SEAL={
  /* true inside OBS when the link carries a key: unsigned = ignored */
  locked:!!URLK,
  key:function(){ return keyHex; },
  /* deck side: trade a correct PIN for the overlay key */
  fetchKey:function(sb,pin){
    if(!pin) return Promise.resolve(null);
    var p=sb.rpc("ov_key",{p_pin:pin}).then(function(r){
      if(r.error||!r.data) return null;
      setKey(String(r.data)); return keyHex;
    },function(){ return null; });
    q=q.then(function(){ return p; });   /* sends wait for the key */
    return p;
  },
  onKey:function(fn){ cbs.push(fn); if(keyHex) try{ fn(keyHex); }catch(e){} },
  /* build an OBS link with the key in it */
  link:function(base,hash){
    return base+(keyHex?("?k="+keyHex):"")+(hash||"");
  },
  send:function(ch,ev,payload){
    if(!ch) return;
    q=q.then(function(){
      if(!keyP){
        try{ ch.send({type:"broadcast",event:ev,payload:payload}); }catch(e){}
        return;
      }
      var t=Date.now(), n=nonce(), j=JSON.stringify(payload===undefined?{}:payload);
      return keyP.then(function(k){ return crypto.subtle.sign("HMAC",k,data(ev,t,n,j)); })
        .then(function(sig){
          try{ ch.send({type:"broadcast",event:ev,payload:{_s:{t:t,n:n,g:hexOf(sig)},j:j}}); }catch(e){}
        })["catch"](function(){});
    });
  },
  on:function(ch,ev,fn){
    ch.on("broadcast",{event:ev},function(m){
      var w=m&&m.payload;
      if(w&&w._s&&typeof w.j==="string"){
        if(!keyP){
          if(SEAL.locked) return;
          try{ fn({payload:JSON.parse(w.j)}); }catch(e){}
          return;
        }
        var s=w._s;
        if(typeof s.t!=="number"||Math.abs(Date.now()-s.t)>WIN) return;
        if(typeof s.n!=="string"||typeof s.g!=="string"||!/^[0-9a-f]{64}$/.test(s.g)) return;
        if(seen[s.n]) return;
        keyP.then(function(k){ return crypto.subtle.verify("HMAC",k,bytes(s.g),data(ev,s.t,s.n,w.j)); })
          .then(function(ok){
            if(!ok||seen[s.n]) return;
            seen[s.n]=Date.now(); prune();
            var p; try{ p=JSON.parse(w.j); }catch(e){ return; }
            fn({payload:p});
          })["catch"](function(){});
        return;
      }
      if(SEAL.locked) return;           /* unsigned: only an unlocked overlay or a deck accepts it */
      fn(m||{});
    });
  },
  /* decks: shout if an overlay in OBS is still running the old, unlocked link */
  watch:function(ch){
    ch.on("presence",{event:"sync"},function(){
      var st=ch.presenceState(), open=false;
      Object.keys(st).forEach(function(k){ st[k].forEach(function(x){
        if((x.role==="overlay"||x.role==="bridge")&&x.locked===false) open=true;
      }); });
      var b=document.getElementById("seal-warn");
      if(open&&!b){
        b=document.createElement("div"); b.id="seal-warn";
        b.style.cssText="position:fixed;left:0;right:0;bottom:0;z-index:99999;background:#ff2e4d;color:#000;"+
          "font:700 12px/1.4 system-ui,sans-serif;letter-spacing:.06em;text-align:center;padding:10px 14px";
        b.textContent="OVERLAY IN OBS IS UNLOCKED — swap its browser source to the new OBS link";
        document.body.appendChild(b);
      }else if(!open&&b){ b.parentNode.removeChild(b); }
    });
  }
};
if(URLK) setKey(URLK);
window.SEAL=SEAL;
})();
