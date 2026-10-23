"""Dynamic DOM-XSS engine (real browser, Playwright).

The static analyzer in `dom.py` *guesses* by regex-matching source->sink in the
page source.  That is heuristic: it cannot tell whether the tainted value
actually reaches the sink at runtime, and it misses compiled framework output
or dynamically-built sinks.  This module closes that gap by **executing** the
page in a real headless browser:

  1. Inject a UNIQUE marker into the attacker-controllable *source*
     (location.hash / location.search / document.cookie / postMessage).
  2. Instrument the dangerous sinks (innerHTML, document.write, eval/Function,
     location.*, jQuery .html/.append/..., setAttribute on* ..., window.open)
     with an init script that runs BEFORE the page's own scripts.
  3. When the marker reaches a sink, record the hit -- and then try to make
     the PAGE ITSELF execute, with executable carrier payloads
     (`_CARRIER_SHAPES`) on the same channel.  Only a dialog fired by the
     page's own code earns the "browser-executed" tier; everything else is
     reported as delivery evidence at a graded severity.

Phase 226 (measured on range6, GATE_STATUS.md): step 2's instrumentation
used to fire ``alert(MARKER)`` ITSELF on every hit, so "executed" was
circular -- the engine's own dialog was the "hard proof", and sanitized
text reaching innerHTML claimed "DOM XSS CONFIRMED".  Delivery to a sink
and execution are different measurements now, and the tiers say which one
was obtained.  If Playwright is unavailable, `analyze()` returns [] and
the caller falls back to the static heuristic.

This is the "real DOM engine" upgrade over static taint analysis.
"""
from __future__ import annotations

import atexit
import json
import logging
import re
import secrets
import threading
import time

from .stealth import marker as _stem_marker

_log = logging.getLogger(__name__)


def _init_script(marker: str) -> str:
    """JS instrumented before page scripts: wraps sinks, records marker hits.

    Phase 226: ``hit()`` no longer fires its own ``alert(MARKER)``.  That
    self-alert was the "hard proof" the whole engine's execution claim
    rested on -- the instrumentation proving its own observation.  It made
    a sanitized page (marker arrives as inert text) indistinguishable from
    a page where attacker code ran.  Execution is now measured by the
    page's OWN dialogs during the carrier wave (see ``analyze`` and
    ``_try_carriers``); this script only records delivery.
    """
    return r"""
(function(){
  var MARKER = "__MARKER__";
  window.__xss_dom_hits = [];
  function hit(sink, snippet){
    window.__xss_dom_hits.push({sink: sink, snippet: String(snippet||'').slice(0,200),
                                via: window.__xss_pm_dispatching ? 'postmsg'
                                     : (window.__xss_dispatching ? 'interaction' : 'auto')});
  }
  // Phase 144: do NOT require a primitive string.  Angular (Trusted Types)
  // hands the innerHTML setter a TrustedHTML wrapper -- typeof is 'object',
  // not 'string' -- so the old check answered "no marker" while the marker
  // was sitting in String(v) all along.  On such a page EVERY innerHTML
  // assignment is an object, so this silently disabled the sink for the
  // whole DOM engine.  Found on OWASP Juice Shop: the hash-routed marker
  // demonstrably reached <span id="searchValue">, the hook demonstrably
  // worked on a manual assignment, and the hit log still read zero.
  // Coercing via String() is what the browser itself does before parsing the
  // value, so a toString() match is a genuine match.
  function has(v){
    if (v == null) return false;
    if (typeof v === 'string') return v.indexOf(MARKER) !== -1;
    try { return String(v).indexOf(MARKER) !== -1; } catch(e) { return false; }
  }

  // innerHTML / outerHTML setters
  ['innerHTML','outerHTML'].forEach(function(prop){
    try {
      var d = Object.getOwnPropertyDescriptor(Element.prototype, prop);
      if (d && d.set){
        var o = d.set;
        Object.defineProperty(Element.prototype, prop, {
          configurable: true, get: d.get,
          set: function(v){ if (has(v)) hit('Element.'+prop, v); return o.call(this, v); }
        });
      }
    } catch(e){}
  });

  // insertAdjacentHTML
  if (Element.prototype.insertAdjacentHTML){
    var oIAH = Element.prototype.insertAdjacentHTML;
    Element.prototype.insertAdjacentHTML = function(p, t){
      if (has(t)) hit('insertAdjacentHTML', t);
      return oIAH.call(this, p, t);
    };
  }

  // Phase 163: URL property sinks.  Phase 167 CORRECTED the list by MEASURING
  // executability instead of assuming it (benchmark/sink_execution.py, headless
  // Chromium; the sentinel is document.title and every shape below runs in the
  // SAME document, so a silent sentinel is real evidence):
  //
  //   iframe.src = 'javascript:...'    -> EXECUTES
  //   iframe.src = 'data:text/html,...'-> inconclusive (opaque origin cannot
  //                                       report), so not claimed here
  //   embed.src / object.data, javascript: or data:text/html -> does NOT
  //                                       execute
  //   a.href = 'javascript:...'        -> does NOT execute, not even on a
  //                                       trusted click in this harness
  //
  // Phase 163 shipped embed/object in this list labelled "executes with no
  // activation", having measured only iframe.src; the engine then reported
  // "(marker executed)" for shapes that execute nothing.  Guarded by URL scheme
  // as well: a plain http src carrying the marker is not a vulnerability.
  var URL_SINKS = [
    [window.HTMLIFrameElement, 'src', 'iframe.src']
  ];
  URL_SINKS.forEach(function(pair){
    var Ctor = pair[0], prop = pair[1], label = pair[2];
    try {
      if (!Ctor || !Ctor.prototype) return;
      var d = Object.getOwnPropertyDescriptor(Ctor.prototype, prop);
      if (!d || !d.set) return;
      var o = d.set;
      Object.defineProperty(Ctor.prototype, prop, {
        configurable: true, enumerable: d.enumerable, get: d.get,
        set: function(v){
          try {
            var s = String(v);
            var m = /^\s*(javascript|data:text\/html)/i.exec(s);
            if (m && has(s)) hit(label + '(' + m[1].toLowerCase() + ')', s);
          } catch(e){}
          return o.call(this, v);
        }
      });
    } catch(e) { /* leave the native accessor alone rather than break the page */ }
  });

  // Phase 162: Range.createContextualFragment.  The static analyzer lists it
  // as a HIGH sink, but the engine never hooked it -- measured with
  // benchmark/sink_matrix.py: a page that parses attacker HTML through a
  // Range was MISS before this hook and HIT after.  Wrapped on the prototype
  // so every Range instance is covered.
  try {
    if (window.Range && Range.prototype.createContextualFragment){
      var oCCF = Range.prototype.createContextualFragment;
      Range.prototype.createContextualFragment = function(html){
        try { if (has(html)) hit('Range.createContextualFragment', html); }
        catch(e){}
        return oCCF.call(this, html);
      };
    }
  } catch(e) { /* leave the native method alone rather than break the page */ }

  // ------------------------------------------------------------------
  // Phase 185: DOMParser 重建链。
  //
  // 这是真实世界里绕过 DOMPurify 类净化的主流写法：先把 HTML 交给
  // DOMParser.parseFromString 解析，再用 importNode / adoptNode 把节点转移
  // 进主文档并插入。此前整条链在引擎里 **零覆盖** —— 既没钩子，也没矩阵形状。
  //
  // 它不能按"参数字符串含标记"来判，理由是被测出来的：
  // benchmark/sink_execution.py 实测 `appendChild(createTextNode(<img
  // onerror=...>))` **不执行**，而 DOMParser 链的 9 个形状全部执行。
  // 只看字符串会把前者也报成 "marker executed"，那是实打实的误报。
  //
  // 所以这里做的是**污点传播 + 插入时复查**：
  //   1. parseFromString 的输入含标记 -> 产出的 document 记为污点源；
  //   2. importNode / adoptNode / cloneNode 把污点传给结果节点；
  //   3. 插入点只在"污点节点"上判定，且要求它**当下**仍含标记——
  //      净化器若已把 onerror 摘掉，outerHTML 里就没有标记，不会命中。
  //
  // 性能：只有污点节点才会走到 outerHTML 序列化（O(1) 的 WeakSet 命中之后），
  // 普通 appendChild 调用几乎零开销。
  // ------------------------------------------------------------------
  var __taintedDocs = new WeakSet();
  var __taintedNodes = new WeakSet();
  function markNode(n){ try { if (n) __taintedNodes.add(n); } catch(e){} }
  function isTainted(n){
    try {
      if (!n) return false;
      if (__taintedNodes.has(n)) return true;
      var doc = (n.nodeType === 9) ? n : n.ownerDocument;
      return doc ? __taintedDocs.has(doc) : false;
    } catch(e) { return false; }
  }
  function serialize(n){
    var t = n.nodeType;
    if (t === 1) return n.outerHTML;
    if (t === 9) return n.documentElement ? n.documentElement.outerHTML : '';
    if (t === 11){
      var tmp = document.createElement('div');
      tmp.appendChild(n.cloneNode(true));
      return tmp.innerHTML;
    }
    return '';
  }
  // 只有能承载可执行结构的节点类型才算命中：Element(1) / Document(9) /
  // DocumentFragment(11)。Text(3) 一律排除 —— 它是那个实测不执行的对照形状。
  function taintedHit(label, n){
    try {
      if (!n || typeof n !== 'object') return;
      if (!isTainted(n)) return;
      var s = serialize(n);
      if (s && s.indexOf(MARKER) !== -1) hit(label, s);
    } catch(e){ /* a node we cannot read is not evidence of anything */ }
  }

  try {
    if (window.DOMParser && DOMParser.prototype.parseFromString){
      var oPFS = DOMParser.prototype.parseFromString;
      DOMParser.prototype.parseFromString = function(str){
        var res = oPFS.apply(this, arguments);
        try { if (has(str)) __taintedDocs.add(res); } catch(e){}
        return res;
      };
    }
  } catch(e) { /* leave the native method alone rather than break the page */ }

  [['importNode','Document.importNode'],
   ['adoptNode','Document.adoptNode']].forEach(function(pair){
    var meth = pair[0];
    try {
      if (!Document.prototype[meth]) return;
      var oT = Document.prototype[meth];
      Document.prototype[meth] = function(node){
        // 污点必须在调用原生方法 **之前** 判定。adoptNode 会把节点迁出原
        // 文档：调用一返回，node.ownerDocument 就已经是主文档了，那时再查
        // 永远是 false —— 整条 adoptNode 链因此静默漏报。importNode 不移动
        // 源节点，所以踩不到这个坑，两种写法在这里统一成"先判后调"。
        // （由 dev/_p185_repro.py 抓到：importNode 命中、adoptNode 静默。）
        var wasTainted = false;
        try { wasTainted = isTainted(node); } catch(e){}
        var res = oT.apply(this, arguments);
        try { if (wasTainted) markNode(res); } catch(e){}
        return res;
      };
    } catch(e){}
  });

  try {
    var oClone = Node.prototype.cloneNode;
    Node.prototype.cloneNode = function(){
      var res = oClone.apply(this, arguments);
      try { if (isTainted(this)) markNode(res); } catch(e){}
      return res;
    };
  } catch(e){}

  ['appendChild','insertBefore','replaceChild'].forEach(function(meth){
    try {
      var oIns = Node.prototype[meth];
      if (!oIns) return;
      Node.prototype[meth] = function(){
        for (var i=0;i<arguments.length;i++) taintedHit('Node.'+meth, arguments[i]);
        return oIns.apply(this, arguments);
      };
    } catch(e){}
  });

  // append / prepend / after / before / replaceWith：字符串参数会被转成
  // **文本节点**（不执行），所以只检查节点参数——又一处"只看字符串就误报"。
  ['append','prepend','after','before','replaceWith'].forEach(function(meth){
    [window.Element, window.CharacterData].forEach(function(Ctor){
      try {
        if (!Ctor || !Ctor.prototype || !Ctor.prototype[meth]) return;
        var oM = Ctor.prototype[meth];
        Ctor.prototype[meth] = function(){
          for (var i=0;i<arguments.length;i++){
            var a = arguments[i];
            if (a && typeof a === 'object') taintedHit(Ctor.name+'.'+meth, a);
          }
          return oM.apply(this, arguments);
        };
      } catch(e){}
    });
  });

  // iframe.srcdoc (property assignment parses the value as a document)
  try {
    var dSD = Object.getOwnPropertyDescriptor(HTMLIFrameElement.prototype, 'srcdoc');
    if (dSD && dSD.set){
      var oSD = dSD.set;
      Object.defineProperty(HTMLIFrameElement.prototype, 'srcdoc', {
        configurable: true, get: dSD.get,
        set: function(v){ if (has(v)) hit('iframe.srcdoc', v); return oSD.call(this, v); }
      });
    }
  } catch(e){}

  // document.write / writeln
  ['write','writeln'].forEach(function(m){
    if (document[m]){
      var o = document[m];
      document[m] = function(){
        for (var i=0;i<arguments.length;i++) if (has(arguments[i])) hit('document.'+m, arguments[i]);
        return o.apply(document, arguments);
      };
    }
  });

  // Function constructor (covers eval-like dynamic code).
  //
  // Phase 141: a plain ``window.Function = function(){...}`` replacement is
  // NOT transparent -- it drops the constructor's own prototype/identity and,
  // critically, breaks frameworks that build their dependency-injection
  // closures with ``new Function(...)``.  Angular does exactly that, and the
  // observable symptom was brutal: the SPA never finished bootstrapping, the
  // marker never reached the page, and every probe silently "found nothing"
  // (confirmed on OWASP Juice Shop: with the override in place the marker was
  // absent from the DOM; with it removed the marker rendered normally).
  // A Proxy forwards apply/construct to the native function, so the marker is
  // still observed while page behaviour stays intact.
  try {
    var OrigFn = window.Function;
    var fnHook = function(args){
      try {
        var code = Array.prototype.map.call(args, String).join(',');
        if (has(code)) hit('Function', code);
      } catch(e){}
    };
    window.Function = new Proxy(OrigFn, {
      apply: function(t, thisArg, args){
        fnHook(args);
        return Reflect.apply(t, thisArg, args);
      },
      construct: function(t, args, newTarget){
        fnHook(args);
        return Reflect.construct(t, args, newTarget);
      }
    });
  } catch(e) { /* leave the native Function alone rather than break the page */ }

  // Phase 161: a direct ``eval(code)`` is NOT covered by the Function hook
  // above -- eval is its own global, it never routes through the Function
  // constructor.  The comment there said "covers eval-like dynamic code",
  // which was an assumption, not a measurement: it is false for eval.
  // Measured cost: the benchmark vector dom_search_eval
  // (``eval(new URLSearchParams(location.search).get('x'))``) never produced
  // a dom_dynamic finding, while its setTimeout twin dom_hash_settimeout
  // did -- same page shape, same marker, same probe.  So a page whose only
  // sink is eval() was unverifiable by the browser engine.
  //
  // The marker check runs BEFORE the call so the hit is recorded even when
  // the evaluated marker is not valid JavaScript (it usually is not: the
  // marker is a bare identifier, so eval throws a ReferenceError -- which is
  // precisely why the payload's *value* must be observed, not its result).
  // Phase 162: the engine's OWN probe code is compiled through this global
  // eval -- page.evaluate() sends a source string -- so a probe that carries
  // the marker (the window_name probe's ``window.name = 'xssentinel_dom_..'``)
  // was indistinguishable from the page evaling attacker data.  Measured
  // cost: two SAFE cases scored as "DOM XSS CONFIRMED" (their payload field
  // was the probe's own source, which is how it was diagnosed).  The harness
  // raises __xss_dom_harness around its own evaluations, synchronously, so
  // page code can never be inside that window.
  try {
    var origEval = window.eval;
    window.eval = function(code){
      try {
        if (!window.__xss_dom_harness && has(code)) {
          hit('eval', String(code));
        }
      } catch(e){}
      return origEval.call(window, code);
    };
  } catch(e) { /* leave the native eval alone rather than break the page */ }

  // setTimeout / setInterval with string body
  ['setTimeout','setInterval'].forEach(function(m){
    var o = window[m];
    window[m] = function(fn, t){
      if (typeof fn === 'string' && has(fn)) hit(m, fn);
      return o.apply(this, arguments);
    };
  });

  // location.assign / replace / href / search / hash / pathname
  //
  // Phase 141: ``location`` is [Unforgeable] -- assigning to its members
  // throws a TypeError in Chrome.  Without this ``try`` the whole IIFE died
  // here, so every hook BELOW this point (window.open, setAttribute, the
  // jQuery wrappers, addEventListener/postMessage) was never installed at
  // all.  Verified with an end-of-script sentinel: before the fix the IIFE
  // never reached its last statement.
  ['assign','replace'].forEach(function(m){
    try {
      if (location[m]){
        var o = location[m];
        location[m] = function(u){ if (has(u)) hit('location.'+m, u); return o.call(location, u); };
      }
    } catch(e){}
  });
  ['href','search','hash','pathname'].forEach(function(p){
    try {
      var d = Object.getOwnPropertyDescriptor(Location.prototype, p);
      if (d && d.set){
        var o = d.set;
        Object.defineProperty(Location.prototype, p, {
          configurable: true, get: d.get,
          set: function(v){ if (has(v)) hit('location.'+p, v); return o.call(this, v); }
        });
      }
    } catch(e){}
  });

  // window.open
  var oOpen = window.open;
  window.open = function(){
    for (var i=0;i<arguments.length;i++) if (has(arguments[i])) hit('window.open', arguments[i]);
    return oOpen.apply(window, arguments);
  };

  // setAttribute with on* handler value
  var oSA = Element.prototype.setAttribute;
  Element.prototype.setAttribute = function(name, val){
    if (typeof name === 'string' && name.toLowerCase().indexOf('on') === 0 && has(val))
      hit('setAttribute('+name+')', val);
    return oSA.call(this, name, val);
  };

  // Phase 197: setAttributeNS delivers an on* handler exactly the same way,
  // and it executes (measured in Chromium: setAttributeNS(null,'onclick',
  // <attacker string>) runs on the next click).  Hooking only setAttribute
  // left the namespaced call invisible to the DOM channel -- a sink we could
  // not see even though the browser honored it.
  var oSAN = Element.prototype.setAttributeNS;
  Element.prototype.setAttributeNS = function(ns, name, val){
    if (typeof name === 'string' && name.toLowerCase().indexOf('on') === 0 && has(val))
      hit('setAttributeNS('+name+')', val);
    return oSAN.apply(this, arguments);
  };

  // setHTMLUnsafe parses attacker HTML with no sanitizer, on the element or a
  // shadow root (XSSMaze `htmlunsafe/level1|5` deliver through the fragment and
  // decodeURIComponent into it).  Chromium fires <img onerror> inserted this
  // way.  Document.parseHTMLUnsafe is the detached-tree form: it is delivery
  // evidence only -- the tree executes when the caller appends it (level4/6).
  ['Element','ShadowRoot'].forEach(function(ctor){
    var C = window[ctor];
    if (C && C.prototype && C.prototype.setHTMLUnsafe){
      var oSU = C.prototype.setHTMLUnsafe;
      C.prototype.setHTMLUnsafe = function(html){
        if (has(html)) hit(ctor + '.setHTMLUnsafe', html);
        return oSU.apply(this, arguments);
      };
    }
  });
  if (window.Document && Document.parseHTMLUnsafe){
    var oDPU = Document.parseHTMLUnsafe;
    Document.parseHTMLUnsafe = function(html){
      if (has(html)) hit('Document.parseHTMLUnsafe', html);
      return oDPU.apply(this, arguments);
    };
  }

  // jQuery sinks (may load after this script)
  function wrapJQ(){
    if (window.jQuery && window.jQuery.fn){
      // Phase 186: 移除了 'text' 与 'val'。benchmark/sink_execution.py 实测
      // （Chromium，sentinel 是 document.title）：
      //   jQuery.text('<img onerror=...>')  -> 不执行（只写文本，HTML 被转义）
      //   jQuery.val('<img onerror=...>')   -> 不执行（只写表单值，不解析）
      // 而这里判的是"参数字符串含标记"，两条都会命中 —— 纯粹的误报，
      // 而且这是本批形状第一次被真正量过：此前这 11 个方法一个都没测过。
      //
      // attr / prop / load 保留：属性值可以是可执行载体（srcdoc、带 javascript:
      // 的 src/href 等），与 setAttribute(on*) 的既有口径一致——on* 需要点击才
      // 触发，但"标记流入事件处理器属性"本身就是漏洞形态，sink_matrix 里
      // setAttribute('onclick') 是 confirm 契约，所以这里不跟着收紧。
      ['html','append','prepend','after','before','replaceWith','attr','prop','load']
        .forEach(function(m){
          if (window.jQuery.fn[m]){
            var o = window.jQuery.fn[m];
            window.jQuery.fn[m] = function(){
              for (var i=0;i<arguments.length;i++) if (has(arguments[i])) hit('jQuery.'+m, arguments[i]);
              return o.apply(this, arguments);
            };
          }
        });
    }
  }
  // 何时包装 jQuery：只在 init 时包一次、再等 DOMContentLoaded 补一次是**不够的**。
  // 页面里同步执行的脚本（内联 script、或直接调用）会在 DOMContentLoaded 之前
  // 就用到 $.append()，那时 fn 还没被包装 —— benchmark/sink_matrix.py 的 jQuery
  // 形状正是这样整批漏掉的（jQuery.html 之所以命中，只是因为它内部走 innerHTML
  // setter，那条路早就 hook 了，跟 wrapJQ 无关）。
  // 所以改成拦截 window.jQuery 的赋值：jQuery 一被挂上来就立刻包装。
  // 下面两行调用保留作兜底（拦截不了的环境、或 jQuery 在 init 前就已存在）。
  var _jqVal = window.jQuery;
  try {
    Object.defineProperty(window, 'jQuery', {
      configurable: true,
      get: function(){ return _jqVal; },
      set: function(v){ _jqVal = v; try { wrapJQ(); } catch(e){} }
    });
  } catch(e) { /* 拦不住就只剩 DOMContentLoaded 那条兜底 */ }
  wrapJQ();
  document.addEventListener('DOMContentLoaded', wrapJQ);

  // postMessage handlers: deliver the marker the way a real attacker can.
  // A cross-origin attacker's postMessage ALWAYS carries the SENDER's origin
  // (or "null" out of a sandboxed iframe) -- the browser forbids forging it
  // to the victim's own origin.  The old harness dispatched the marker with
  // origin = location.origin, so a handler that VALIDATES origin still fired
  // the sink and the engine confirmed a cross-origin XSS no attacker could
  // reach.  Both dispatches below use attacker-reachable origins only; a
  // handler with effective origin validation stays silent, and that silence
  // is the measured verdict (DOM Invader's origin-spoof mode, in-harness).
  var PM_ORIGINS = ["https://attacker.example", "null"];
  function pmFire(handler){
    setTimeout(function(){
      for (var i = 0; i < PM_ORIGINS.length; i++){
        try { window.__xss_pm_dispatching = 1;
              handler({ data: MARKER, origin: PM_ORIGINS[i],
                        source: null, isTrusted: true }); }
        catch(e){}
        finally { window.__xss_pm_dispatching = 0; }
      }
    }, 50);
  }
  // Phase 226: keep the handlers so the carrier wave can re-dispatch them
  // with an executable payload (data = carrier) on the same page, instead
  // of baking one fixed message into the closure.  The initial pmFire
  // above is unchanged: wave 0 still delivers the bare marker.
  window.__xss_dom_pm = [];
  var oAE = window.addEventListener;
  window.addEventListener = function(type, handler, opts){
    if (type === 'message' && typeof handler === 'function'){
      window.__xss_dom_pm.push(handler);
      pmFire(handler);
    }
    return oAE.call(window, type, handler, opts);
  };
  // Handlers registered by property instead of addEventListener reach the
  // same dispatch: wrap the onmessage setter (init script runs before any
  // page script, so the property is still a plain slot when we get here).
  try {
    var _omVal;
    Object.defineProperty(window, 'onmessage', {
      configurable: true,
      set: function(fn){ _omVal = fn;
                         if (typeof fn === 'function') {
                           window.__xss_dom_pm.push(fn); pmFire(fn);
                         } },
      get: function(){ return _omVal; }
    });
  } catch(e){}
})();
""".replace("__MARKER__", marker)


_CLIENT_JS_RE = re.compile(
    r"<script\b|on\w+\s*=|javascript:|addEventListener\(\s*['\"]message|"
    r"ng-app|v-html|dangerouslySetInnerHTML", re.I)


def _normalize_harvest(raw: dict, url: str, max_names: int = 200,
                       max_urls: int = 50, max_routes: int = 25) -> dict:
    """Phase 196: normalize one harvest -> (names, same-origin resource URLs,
    hash routes).

    The raw evaluate result is untrusted page output: names are kept
    non-empty strings only; resource URLs must parse as http(s) AND match
    the target's host exactly (the operator named THIS host -- a
    third-party analytics call is someone else's system, mirroring the
    Phase 176l import scope rule).  Both lists dedup in first-seen order
    and are capped.
    """
    from urllib.parse import urlparse
    out: dict = {"names": [], "resource_urls": [], "routes": []}
    if not isinstance(raw, dict):
        return out
    host = urlparse(url).netloc.lower()
    seen_n: set = set()
    for n in (raw.get("names") or []):
        if isinstance(n, str) and n.strip() and n not in seen_n:
            seen_n.add(n)
            out["names"].append(n)
            if len(out["names"]) >= max_names:
                break
    seen_u: set = set()
    for u in (raw.get("urls") or []):
        if not isinstance(u, str):
            continue
        p = urlparse(u)
        if p.scheme not in ("http", "https") or p.netloc.lower() != host:
            continue
        clean = u.split("#", 1)[0]
        if clean in seen_u:
            continue
        seen_u.add(clean)
        out["resource_urls"].append(clean)
        if len(out["resource_urls"]) >= max_urls:
            break
    # Phase 210: the hash routes the RENDERED page links to.  A SPA on hash
    # location strategy (Angular `useHash`) renders its nav as href="#/search",
    # and a fragment never reaches the server -- so an HTTP-only discovery
    # pass cannot learn these pages exist, while the router does read them and
    # they are where client-side sinks live.  Measured on OWASP Juice Shop
    # 20.2.0: the crawl path finds these by mining the bundle, but --discover
    # and the Agent-facing xssentinel_discover returned nothing route-shaped.
    #
    # Same-origin is structural, not filtered: the selector only yields hrefs
    # that start with "#/", so joining one to the rendered URL cannot leave
    # that origin.  The fragment is kept INTACT (unlike resource_urls, where
    # it is stripped): "?q=" inside the fragment is the whole point.
    seen_r: set = set()
    root = url.split("#", 1)[0]
    for r in (raw.get("routes") or []):
        if not isinstance(r, str) or not r.startswith("#/"):
            continue
        target = root + r
        if target in seen_r:
            continue
        seen_r.add(target)
        out["routes"].append(target)
        if len(out["routes"]) >= max_routes:
            break
    return out


def interaction_dispatch_js(needle: str) -> str:
    """Phase 193: JS that dispatches synthetic interaction events on every
    element carrying ``needle`` (the probe token / DOM marker).

    Requires-interaction handlers (``onpointerdown``/``onclick``/... from
    the ``interaction_events`` corpus) are live attributes the moment they
    reflect -- the only thing missing is the interaction, which an
    attacker performs and a scanner must simulate.  DOM Invader clicks;
    we dispatch the bounded event set below on each marker-bearing
    element.  Untrusted dispatch (``isTrusted=false``) means handlers that
    check it under-fire -- an under-measurement, never an over-claim.

    Events are bounded (first 30 matching elements among the first 500)
    and the whole loop is one ``page.evaluate`` call.  While dispatching,
    ``window.__xss_dispatching`` is set so the sink harness can attribute
    hits to an interaction.
    """
    return r"""
(function(){
  var NEEDLE = __NEEDLE__;
  var EVTS = [["pointerdown","PointerEvent"],["pointerup","PointerEvent"],
    ["pointermove","PointerEvent"],["pointerover","PointerEvent"],
    ["pointerout","PointerEvent"],["pointerenter","PointerEvent"],
    ["gotpointercapture","PointerEvent"],["lostpointercapture","PointerEvent"],
    ["mousedown","MouseEvent"],["mouseup","MouseEvent"],
    ["mousemove","MouseEvent"],["mouseover","MouseEvent"],
    ["mouseout","MouseEvent"],["mouseenter","MouseEvent"],
    ["dblclick","MouseEvent"],["wheel","WheelEvent"],["click","MouseEvent"],
    ["copy","ClipboardEvent"],["paste","ClipboardEvent"],
    ["dragstart","DragEvent"],["dragover","DragEvent"],["drop","DragEvent"],
    ["dragend","DragEvent"],["dragleave","DragEvent"],
    ["touchstart","Event"],["touchmove","Event"],["touchend","Event"],
    ["touchcancel","Event"],
    ["keydown","KeyboardEvent"],["keyup","KeyboardEvent"],
    ["keypress","KeyboardEvent"],
    ["submit","Event"],["invalid","Event"],["select","Event"],
    ["input","Event"],["beforeinput","Event"],["reset","Event"],
    ["search","Event"],["cut","Event"],["selectstart","Event"],
    ["toggle","Event"],["beforetoggle","Event"],
    ["fullscreenchange","Event"],["scroll","Event"],
    ["mouseleave","MouseEvent"],["pointerleave","PointerEvent"],
    ["focusout","FocusEvent"],["focusin","FocusEvent"],
    ["selectionchange","Event"],["cancel","Event"],["afterprint","Event"],
    ["pause","Event"],["play","Event"],["volumechange","Event"],
    ["ratechange","Event"],["seeking","Event"],["seeked","Event"],
    ["ended","Event"],["waiting","Event"],["canplay","Event"],
    ["loadedmetadata","Event"],["durationchange","Event"],
    ["progress","Event"],["suspend","Event"]];
  window.__xss_dispatching = 1;
  var n = 0;
  try {
    var all = document.body ? document.body.querySelectorAll("*") : [];
    var els = [];
    for (var i = 0; i < all.length && els.length < 30; i++){
      if (i >= 500) break;
      try {
        if ((all[i].outerHTML || "").indexOf(NEEDLE) !== -1) els.push(all[i]);
      } catch(e){}
    }
    for (var k = 0; k < els.length; k++){
      var el = els[k];
      for (var j = 0; j < EVTS.length; j++){
        try {
          var C = window[EVTS[j][1]] || Event;
          el.dispatchEvent(new C(EVTS[j][0], {bubbles: true, cancelable: true}));
          n++;
        } catch(e){
          try { el.dispatchEvent(new Event(EVTS[j][0], {bubbles: true})); n++; }
          catch(e2){}
        }
      }
      try { if (el.focus) el.focus(); } catch(e){}
    }
  } catch(e) {}
  window.__xss_dispatching = 0;
  return n;
})()
""".replace("__NEEDLE__", json.dumps(needle))


# ---------------------------------------------------------------------------
# Shared headless browser (Phase 38 / P1-6): ONE Chromium per THREAD, reused
# across analyze() and verify_headless() calls.  Launching a browser costs
# ~1-2s and the old code paid it for every single confirmation.  Instances
# are thread-local (playwright sync objects are thread-bound) and registered
# for atexit cleanup.  Callers own PAGES, never the browser: create pages
# freely and close them; do NOT close the shared browser.
# ---------------------------------------------------------------------------
_TLS = threading.local()
_ALL_BROWSERS: list[tuple] = []
_BROWSER_LOCK = threading.Lock()


def get_shared_browser():
    """Return a thread-bound, reused headless Chromium instance."""
    b = getattr(_TLS, "browser", None)
    if b is not None:
        try:
            if b.is_connected():
                return b
        except Exception:
            pass
        # Phase 224: a DEAD thread-local browser (Chromium crashed / was
        # OOM-killed / died with host pressure) used to be a one-way door.
        # Its playwright instance left a greenlet loop parked in THIS
        # thread, so the _loop_running() guard below refused every later
        # launch and every analyze()/verify_headless()/harvest() in this
        # thread silently returned nothing for the rest of the process --
        # the silent-FN direction.  Measured as the test_range5 live-pair
        # flake ("all findings: []" after a 13h suite run;
        # dev/_stale_browser_probe.py reproduces it deterministically).
        # Unwind the stale instance FIRST: shutdown_thread_browser() parks
        # the old loop out of the way (verified: loop stops, relaunch
        # succeeds -- dev/_stale_unwind_probe.py), then the launch below
        # runs clean.
        shutdown_thread_browser()
    # Playwright's sync API runs its asyncio loop *in the calling thread*
    # (greenlet-based).  Starting it while a loop is already running here
    # corrupts that loop and breaks every later asyncio.run() in the
    # process -- refuse loudly instead; callers catch and degrade to static
    # analysis.
    if _loop_running():
        raise RuntimeError(
            "cannot start Playwright sync API: this thread already has a "
            "running event loop (would break asyncio.run() afterwards); "
            "use dom_engine='static' or run from a loop-free thread")
    from playwright.sync_api import sync_playwright
    pw = sync_playwright().start()
    b = pw.chromium.launch(args=["--no-sandbox"])
    _TLS.pw = pw
    _TLS.browser = b
    with _BROWSER_LOCK:
        _ALL_BROWSERS.append((pw, b))
    return b


def _loop_running() -> bool:
    """True when the calling thread currently has a *running* asyncio loop."""
    import asyncio
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return False
    return True


def shutdown_thread_browser() -> None:
    """Stop THIS thread's shared Playwright instance, if any.

    The shared browser exists to amortize Chromium startup across scans, but
    its sync API leaves the thread's asyncio loop permanently running -- any
    later ``asyncio.run()`` in the same thread then fails with "cannot be
    called from a running event loop".  Embedders and test harnesses that
    mix sync Playwright with asyncio must call this when done with dynamic
    DOM analysis to unwind the loop.
    """
    pw = getattr(_TLS, "pw", None)
    b = getattr(_TLS, "browser", None)
    if pw is None and b is None:
        return
    with _BROWSER_LOCK:
        _ALL_BROWSERS[:] = [
            (p, br) for (p, br) in _ALL_BROWSERS if p is not pw]
    _TLS.pw = None
    _TLS.browser = None
    if b is not None:
        try:
            b.close()
        except Exception:
            pass
    if pw is not None:
        try:
            pw.stop()  # stops the greenlet-driven loop in this thread
        except Exception:
            pass


@atexit.register
def _shutdown_shared_browsers():
    """Best-effort cleanup of every thread's browser at interpreter exit."""
    with _BROWSER_LOCK:
        instances, _ALL_BROWSERS[:] = _ALL_BROWSERS[:], []
    for pw, b in instances:
        try:
            b.close()
        except Exception:
            pass
        try:
            pw.stop()
        except Exception:
            pass


def page_has_client_js(html: str) -> bool:
    """Quick pre-filter: only spend a browser session on pages that actually
    run client-side JS (skip plain HTML to save time)."""
    return bool(_CLIENT_JS_RE.search(html or ""))


# Phase 154 (as written) / Phase 159 (inverted).  A browser pass costs ~5.6s
# (9 probes x ~700ms settle); 41 of the 57 slow benchmark cases paid it
# without needing it (~25% of the run, see benchmark/speed_profile.py).
#
# Phase 154 implemented the filter as a SINK WHITELIST: "run the browser only
# if we can see a sink pattern in the inline script".  That is backwards --
# every sink the regex does not name becomes unverifiable.  Measured cost
# (this session, full regression 20260918-011159):
#   * tests/test_async_dom_live.py went red -- its page is
#     ``document.getElementById('f').srcdoc = decodeURIComponent(...)``.
#     ``srcdoc`` is a real sink (an attacker-controlled srcdoc executes
#     script) and it matches nothing in the Phase 154 pattern list.
#   * tests/test_async_deep.py went red the same way.
# The Phase 154 commit also claimed "conservative by construction: anything
# the regexes cannot parse is let through by the caller keeping the old
# page_has_client_js check".  That is false: the caller ANDs the two checks,
# so combining them can only ever be NARROWER than either alone.
#
# Phase 159 inverts the question.  Instead of "is there evidence of a sink?"
# it asks "can we PROVE this page cannot execute anything?"  Only provably
# inert pages (literal/JSON declarations, no call, no member write, no DOM
# global) are skipped.  Unknown constructs now get the browser, which is the
# direction a recall-first scanner must err on.
_CAN_EXEC_RE = re.compile(
    # any call or grouping -- a sink is almost always a call
    r"\(|\)"
    # function bodies / dynamic code
    r"|=>|\bfunction\b|\bclass\b|\bnew\b|\beval\b|\bFunction\b|\batob\b|"
    r"\bimport\b|\brequire\b|\bsetTimeout\b|\bsetInterval\b"
    # a DOM/BOM global -- the page can reach the document, so it can sink
    r"|\b(?:document|window|location|navigator|history|screen|self|top|"
    r"parent|frames|globalThis|localStorage|sessionStorage|alert|fetch|"
    r"XMLHttpRequest|URLSearchParams|URL|postMessage|open|cookie|referrer|"
    r"innerHTML|outerHTML|srcdoc|javascript)\b"
    # member assignment:  a.b = c
    r"|\.[A-Za-z_$][\w$]*\s*=[^=]", re.I)
_EXT_SCRIPT_RE = re.compile(r"<script[^>]*\ssrc\s*=", re.I)
_INLINE_SCRIPT_RE = re.compile(
    r"<script(?![^>]*\ssrc\s*=)[^>]*>(.*?)</script>", re.I | re.S)
# Execution that lives in markup, not in a <script> block: inline event
# handlers, javascript: URLs, an attacker-settable srcdoc/data attribute.
_HTML_EXEC_RE = re.compile(
    r"\son[a-z]+\s*=|:javascript|javascript:|\ssrcdoc\s*=|data:text/html",
    re.I)


def page_can_run_sink(html: str) -> bool:
    """Pre-filter: can this page execute code that could reach a sink?

    Used together with :func:`page_has_client_js` -- passing both means the
    page is worth a real-browser pass.  Phase 159: this answers "is the page
    provably inert?", NOT "did we recognise a sink?".  True for anything we
    cannot see inside (external scripts, unparseable script bodies, DOM
    globals), so the filter can only ever SKIP a browser session that cannot
    possibly produce a DOM finding.
    """
    if not html:
        return False
    if _EXT_SCRIPT_RE.search(html):
        return True
    if _HTML_EXEC_RE.search(html):
        return True
    for body in _INLINE_SCRIPT_RE.findall(html):
        if _CAN_EXEC_RE.search(body or ""):
            return True
    return False


# Upper bound on "swap a real query parameter for the marker" probes, so a
# URL with dozens of parameters cannot multiply the browser cost.
_MAX_SEARCH_PARAM_PROBES = 4

# Phase 141: how long to let a page settle after navigation before reading
# the sink log.  ``page.goto()`` returns once the load event fires, but an
# SPA renders its route *after* that -- reading immediately returns an empty
# hit log, so every probe on a client-rendered page looked like a miss.  A
# page that renders synchronously pays this once per goto probe; the default
# probe set has ~8, so the cost is bounded and only paid when the DOM engine
# is actually enabled.
_DOM_SETTLE_MS = 700

# Phase 241: write-face reaping.  A modern SPA has no <form action> -- its
# write requests are emitted by component code when the operator clicks
# something.  So the face is OBSERVED, not inferred: fill the page's named
# inputs with a marker, click a bounded set of buttons, and keep the
# requests whose body carries the marker.  Measured on OWASP Juice Shop
# (Phase 240): 60 endpoints, L4_stored ran 0 times because every form had
# no action; this probe recovered POST /api/Complaints/ + field
# "message" from the page's own fetch call.
#
# Clicking is a REAL side effect (an admin session's "delete user" button
# is destructive), so this is opt-in and the button set is deny-listed.
_WRITE_FACE_MARK = "wf7k"
_WRITE_FACE_DENY = (
    "delete", "remove", "logout", "log out", "sign out", "signout",
    "reset", "clear", "cancel", "close", "discard", "revoke",
)
_WRITE_FACE_SETTLE_MS = 900
_WRITE_FACE_MAX_FACES = 20

# The request log: installed on the page after load and BEFORE any click,
# so it captures the requests the interaction causes.  Read once, discarded
# with the page.
_WRITE_FACE_LOGGER_JS = r"""
(function(){
  if (window.__wf_log) { return; }
  window.__wf_log = [];
  var push = function(kind, method, url, body, ct){
    try {
      window.__wf_log.push({kind: kind, method: String(method||'GET').toUpperCase(),
        url: String(url||''), body: String(body||'').slice(0, 400),
        ct: String(ct||'')});
    } catch(e){}
  };
  var of = window.fetch;
  window.fetch = function(input, init){
    try {
      var u = (typeof input === 'string') ? input : (input && input.url);
      var b = (init && init.body !== undefined && init.body !== null)
        ? (typeof init.body === 'string' ? init.body : '[nonstring]')
        : '';
      var h = (init && init.headers) ? init.headers : null;
      var ct = (h && (h.get ? h.get('content-type') : h['Content-Type'])) || '';
      push('fetch', (init && init.method) || 'GET', u, b, ct);
    } catch(e){}
    return of.apply(this, arguments);
  };
  var oo = XMLHttpRequest.prototype.open;
  var os = XMLHttpRequest.prototype.send;
  XMLHttpRequest.prototype.open = function(m, u){ this.__wf_m = m; this.__wf_u = u; return oo.apply(this, arguments); };
  XMLHttpRequest.prototype.send = function(b){
    try {
      var ct = '';
      try { ct = this.getResponseHeader('content-type') || ''; } catch(e){}
      push('xhr', this.__wf_m, this.__wf_u,
           (typeof b === 'string' ? b : ''), ct);
    } catch(e){}
    return os.apply(this, arguments);
  };
})();
"""

# Fills every named text control with a marker derived from its field name,
# so a body can be attributed to the field that carried it.  The harness
# flag mirrors Phase 193's interaction dispatch: our own writes must not be
# recorded as page-initiated script execution.
_WRITE_FACE_FILL_JS = r"""
(function(mark){
  var out = [];
  var ctrls = document.querySelectorAll(
    "input:not([type=hidden]):not([type=checkbox]):not([type=radio]),textarea");
  ctrls.forEach(function(el){
    var id = el.getAttribute('name') || el.getAttribute('formcontrolname')
             || el.id || '';
    if (!id) return;
    var v = mark + String(id).replace(/[^A-Za-z0-9]/g, '');
    try { el.value = v; el.dispatchEvent(new Event('input', {bubbles:true})); } catch(e){}
    out.push(String(id));
  });
  try { window.__xss_dom_harness = 1; } catch(e){}
  return out;
})(%s)
"""

# Picks and clicks ONE button -- the most submit-like one outside the
# navigation chrome.  Phase 241: clicking several in a loop was measured to
# be wrong twice over: the first six buttons on a Material page are the nav
# bar (so the submit button was never reached), and an SPA navigates away
# after the first click anyway.  One click, best candidate, is both safer
# and sufficient -- the log is read after it.
_WRITE_FACE_PICK_JS = r"""
(function(deny){
  var btns = Array.from(document.querySelectorAll(
    "button, [role=button], input[type=submit]"));
  var SUBMIT = ['send', 'submit', 'save', 'post', 'apply', 'confirm',
                'create', 'add', 'register', 'sign up', 'update'];
  var MIN_SCORE = 5;   // submit-like text, type=submit, or inside a form
  var best = null, bestScore = MIN_SCORE - 1;
  btns.forEach(function(b){
    if (b.disabled) return;
    if (b.closest('nav, header, mat-toolbar, mat-drawer, .navbar, footer')) return;
    var txt = ((b.textContent || '') + ' ' +
               (b.getAttribute('aria-label') || '') + ' ' +
               (b.getAttribute('title') || '')).toLowerCase();
    for (var d = 0; d < deny.length; d++) {
      if (txt.indexOf(deny[d]) >= 0) return;      // deny-listed: never
    }
    var score = 0;
    for (var s = 0; s < SUBMIT.length; s++) {
      if (txt.indexOf(SUBMIT[s]) >= 0) { score += 10; break; }
    }
    var isSubmit = (b.getAttribute('type') || '') === 'submit';
    if (isSubmit) score += 5;
    if (b.closest('form')) score += 3;
    if (b.tagName === 'MAT-FLAT-BUTTON' || b.tagName === 'MAT-RAISED-BUTTON'
        || b.tagName === 'MAT-BUTTON' || b.tagName === 'BUTTON') score += 1;
    // Phase 242: an icon-only control with no accessible name is never the
    // write action -- clicking it is useless at best and a destructive icon
    // at worst.  It must ALSO be a submit: an empty-text button inside a
    // form is plausible; an empty-text button outside one is not.
    if (!txt.trim() && !(isSubmit && b.closest('form'))) score = 0;
    if (score > bestScore) { bestScore = score; best = b; }
  });
  if (!best) return '';
  try { window.__xss_dom_harness = 1; best.click(); } catch(e){}
  try { window.__xss_dom_harness = 0; } catch(e){}
  return ((best.textContent || '').trim().slice(0, 40) || '(icon)');
})(%s)
"""

# Phase 147: total wall-clock budget for probing ONE url.
#
# Each goto probe waits up to ``timeout`` seconds for its own navigation, so
# a page that pulls a slow or unreachable third-party resource makes every
# probe pay that timeout in turn -- eight probes times twenty seconds is far
# past any scan-level cap, and the whole scan dies with it.  Measured on
# benchmark pos-sri-01 and pos-importmap-01 (pages referencing
# cdn.example): both hit the 90s scan timeout with zero requests recorded,
# and both do so identically on the pre-Phase-144 code, so this is not a
# regression from that work -- it is the DOM engine waiting without bound.
#
# Same reasoning as _DOM_SETTLE_MS: the engine's job is to observe the
# page's own behaviour, and it must do so within a fixed cost.  Once the
# budget is gone we stop probing and return whatever was already found --
# findings are collected per-probe, so a slow tail never costs the head.
# 30s (not more): the benchmark's per-case cap is 45s, and the scan also
# spends time on the baseline and its own layers -- a DOM budget that eats
# most of a case's wall clock turns "slow page" into "case timeout", which
# reads as an error rather than a result.
_DOM_PROBE_BUDGET_S = 30.0

# Phase 226: executable carrier shapes for the confirmation wave.
#
# Wave 0 delivers a BARE marker: it answers "does this source reach a sink"
# for every channel, including ones that build the payload themselves
# (``iframe.src = 'javascript:' + q``).  A bare token, though, arrives
# intact even through a sanitizer -- it contains nothing to strip -- so a
# reachability hit alone cannot tell "attacker code would run here" from
# "inert text landed in innerHTML" (measured: range6's safe twin, where
# DOMPurify strips the payload but the marker survived as text and the
# engine claimed "marker executed").
#
# So when a hit stands and no dialog has been observed, the same channel is
# replayed with these shapes; ONLY a dialog fired by the page's own code
# earns "browser-executed".  Shape order matters: HTML first (innerHTML/
# document.write/jQuery family -- most common), then the JS shape (eval /
# setTimeout(string) / Function family), then the URL scheme (iframe.src
# family; measured executable in Phase 163).
#
# The alert argument is a NUMBER (%d), not a quoted string, and that is a
# measured design requirement, not taste: range4's fixture reflects the
# param into a single-quoted JS config line (`{q: '{value}'}`), so a
# carrier containing `'` closes the string and the whole script fails
# syntax -- the page never runs, no dialog fires, and a genuinely
# vulnerable page measures as delivery-only.  A decimal token survives
# every string/attribute context a real app interpolates into.
_CARRIER_SHAPES = (
    ("html", "<img src=x onerror=alert(%d)>"),
    ("js", "alert(%d)"),
    ("url", "javascript:alert(%d)"),
    # Phase 265: range6 measured this form/math/mglyph namespace-confusion
    # shape survives DOMPurify 2.0.7 and is stripped by 3.4.17.  The generic
    # html/js/url carriers cannot get through either build, so without this
    # shape a KNOWN-vulnerable sanitizer page could only ever earn a low
    # delivery hint.  The page's own dialog is still the proof.
    ("mxss", "<form><math><mtext></form><form><mglyph><style></math>"
             "<img src onerror=alert(%d)>"),
)

# Phase 226: cap on carrier-wave navigations per analyze() call.  Wave 1 is
# only paid when a hit exists without a dialog, and one dialog proves the
# channel; the cap keeps a page with many reachable channels from turning
# its probe budget into carrier replays.
_DOM_CARRIER_WAVE_MAX = 4


def _carrier_token(marker: str) -> str:
    """Deterministic decimal token the carrier dialogs carry (Phase 226).

    Derived from the marker so every carrier shape and every dialog check
    agree, and reproducible across calls.  Always exactly ten digits, no
    leading zero (``alert(0123...)`` would be a legacy-octal SyntaxError in
    sloppy mode).  Ten random digits make an exact-match collision with
    anything else a page might alert negligible, and the value carries no
    quotes, spaces or percent-encoded characters -- the form survives every
    string/attribute interpolation context our carrier shapes ride through.
    """
    import hashlib
    h = int(hashlib.sha256(marker.encode("utf-8")).hexdigest()[:12], 16)
    return str(1_000_000_000 + (h % 9_000_000_000))

# Phase 200: budget for the post-failure recovery navigation (see
# _recover_nav).  Measured at 0.02s against a silent server -- 5s is a
# bound, not an expectation; about:blank needs no network round-trip, so
# hitting this cap means the BROWSER is wedged, not the target.
_RECOVER_TIMEOUT_S = 5000


def _recover_nav(page) -> None:
    """Cancel a failed/provisional navigation so the page is evaluable again.

    Phase 200, measured (dev/_silent_nav_probe.py, three branches against a
    server that accepts and never responds):

      A  goto(wait_until="commit", timeout=2s) raises after 2.02s, then
         ``page.evaluate`` blocks **763s** -- Chromium keeps the navigation
         provisional and Playwright's evaluate waits for an execution
         context that never arrives (probe A ended with "Execution context
         was destroyed").  In the field this was a 436s stall inside
         scan_endpoint('/evt'), and faulthandler could not name it: the
         thread sits in Playwright's greenlet event loop, so the dump shows
         asyncio frames and nothing about the page.
      B  after the same failed goto, ``page.goto("about:blank")`` returns
         in **0.02s** and the following evaluate in **0.0s**.
      C  control evaluate without a dangling navigation: 0.0s.

    Best-effort by design: if the recovery navigation itself fails the
    page is left as-is and the caller's next Playwright call raises
    normally -- recovery must never turn one failure into a crash.
    """
    try:
        page.goto("about:blank", timeout=_RECOVER_TIMEOUT_S)
    except Exception:
        pass


def _query_param_names(url: str) -> list:
    """Ordered, de-duplicated query parameter names of ``url``."""
    from urllib.parse import urlparse, parse_qsl
    try:
        pairs = parse_qsl(urlparse(url).query, keep_blank_values=True)
    except Exception:
        return []
    names: list = []
    seen: set = set()
    for key, _value in pairs:
        if key and key not in seen:
            seen.add(key)
            names.append(key)
    return names


def _with_param_value(url: str, name: str, value: str) -> str:
    """Return ``url`` with query parameter ``name`` set to ``value``.

    Every other parameter keeps its original value so pages that branch on
    them still reach the same code path.
    """
    from urllib.parse import urlparse, urlunparse, urlencode, parse_qsl
    parsed = urlparse(url)
    pairs = parse_qsl(parsed.query, keep_blank_values=True)
    out = [(k, value if k == name else v) for k, v in pairs]
    if not any(k == name for k, _v in pairs):
        out.append((name, value))
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path,
                       parsed.params, urlencode(out), ""))


# ---------------------------------------------------------------------------
# SPA hash routing (``http://h/#/search?q=1``) -- Phase 141
#
# The query lives *inside* the fragment, so ``urlparse().query`` is empty
# and every parameter-discovery path used to miss it.  Only the browser can
# see these values (an HTTP request never carries the fragment), so unlike
# ordinary parameters they are a DOM-XSS concern only -- which is also why
# fixing this in the DOM engine is enough.
# ---------------------------------------------------------------------------

def _hash_route_query(url: str) -> str:
    """Query string carried inside the URL fragment, or ``""``.

    ``http://h/#/search?q=1`` -> ``q=1``.  A fragment without a ``?``
    (``#/search``) yields ``""``.
    """
    from urllib.parse import urlparse
    try:
        frag = urlparse(url).fragment
    except Exception:
        return ""
    if not frag:
        return ""
    _, sep, query = frag.partition("?")
    return query if sep else ""


def _hash_param_names(url: str) -> list:
    """Ordered, de-duplicated names of the fragment-carried parameters."""
    from urllib.parse import parse_qsl
    try:
        pairs = parse_qsl(_hash_route_query(url), keep_blank_values=True)
    except Exception:
        return []
    names: list = []
    seen: set = set()
    for key, _value in pairs:
        if key and key not in seen:
            seen.add(key)
            names.append(key)
    return names


def _with_hash_param_value(url: str, name: str, value: str) -> str:
    """Set a fragment-carried parameter, keeping the route path intact.

    ``http://h/#/search?q=1`` + ``name='q'`` + ``value=MK`` becomes
    ``http://h/#/search?q=MK``.  The ``/search`` route must survive: drop it
    and the SPA renders a different view (usually its 404), so the sink is
    never reached and the probe silently proves nothing.
    """
    from urllib.parse import urlparse, urlunparse, urlencode, parse_qsl
    parsed = urlparse(url)
    route, sep, query = parsed.fragment.partition("?")
    pairs = parse_qsl(query, keep_blank_values=True) if sep else []
    out = [(k, value if k == name else v) for k, v in pairs]
    if not any(k == name for k, _v in pairs):
        out.append((name, value))
    new_fragment = route + "?" + urlencode(out)
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path,
                       parsed.params, parsed.query, new_fragment))


def _auth_cookie_dicts(cookies: list, url: str) -> list[dict]:
    """Build the cookie dicts Playwright's ``add_cookies`` wants.

    Phase 174: ``url`` and ``path`` are **mutually exclusive** for Playwright.
    Passing a bare ``path`` next to ``url`` makes the whole call raise
    "Cookie should have either url or path", which is how this used to fail:
    the old code always set ``path`` and then ALSO set ``url`` whenever the
    cookie carried no domain -- exactly the manual ``--cookie`` jar -- so the
    batch was rejected, the exception was swallowed into a debug line, and the
    browser session stayed silently anonymous.  Authenticated scans then
    rendered 403 route shells and every sink behind a login was invisible
    (measured on Juice Shop's server-side XSS challenge, Phase 173).

    So: domain present -> {domain, path}; domain absent -> {url} and no path.
    """
    from urllib.parse import urlparse
    origin = "{0.scheme}://{0.netloc}".format(urlparse(url))
    out: list[dict] = []
    for c in cookies:
        cd = {"name": c.get("name"), "value": c.get("value", "")}
        if c.get("domain"):
            cd["domain"] = c["domain"]
            cd["path"] = c.get("path") or "/"
        else:
            cd["url"] = origin
        out.append(cd)
    return out


class DynamicDomAnalyzer:
    """Runs a real headless browser to confirm DOM-XSS sinks execute."""

    def __init__(self, timeout: int = 20, headless: bool = True,
                 auth_headers: dict | None = None,
                 auth_cookies: list | None = None,
                 auth_local_storage: dict | None = None):
        # `timeout` is in SECONDS (caller-facing). Playwright's goto/wait APIs
        # expect MILLISECONDS, so we multiply at the boundary below.
        self.timeout = timeout
        self.headless = headless
        # Phase 150: replicate the authenticated session in the browser.
        # requests.Session headers/cookies never reach Playwright on their
        # own; without them the confirmation layer visits authenticated
        # routes anonymously (401 / login wall) and every sink behind the
        # login is invisible to it.
        self.auth_headers: dict = dict(auth_headers or {})
        self.auth_cookies: list = list(auth_cookies or [])
        # SPA route guards commonly read the token from localStorage even
        # when API calls authenticate via cookie/header (observed: Juice
        # Shop renders its 403 route shell with a valid session cookie).
        # Seeded via init script, SCOPED to the scan origin -- an init
        # script runs in every frame, and localStorage is per-origin, so
        # an unscoped seed would copy the session token into the storage
        # of any third-party origin the page embeds.
        self.auth_local_storage: dict = dict(auth_local_storage or {})

    @staticmethod
    def _marker_field(body: str, marker: str) -> str:
        """The API field that carried the marker, parsed out of the body.

        JSON and form bodies both work, and a wrong answer here is worse
        than none: the stored layer injects INTO this field name, and the
        control's own id is often not the API field (Juice Shop: control id
        "complaintMessage", API field "message").
        """
        if not body or marker not in body:
            return ""
        import json as _json
        from urllib.parse import parse_qs
        text = body.strip()
        if text[:1] in ("{", "["):
            try:
                data = _json.loads(text)
            except Exception:
                data = None
            if isinstance(data, dict):
                # Nested leaves are checked BEFORE the top level: a marker
                # inside {"user":{"bio":...}} also matches str({"bio":...}),
                # and the leaf is where the marker actually travelled.
                # (Honest limit, recorded: the stored layer injects a flat
                # {field: payload} body, so a nested face may not reproduce
                # the shape on injection -- the round-trip then confirms
                # nothing, which is the correct outcome.)
                for k, v in data.items():
                    if isinstance(v, dict):
                        for k2, v2 in v.items():
                            if marker in str(v2):
                                return str(k2)
                for k, v in data.items():
                    if marker in str(v):
                        return str(k)
        try:
            for k, vals in parse_qs(text, keep_blank_values=True).items():
                if any(marker in str(v) for v in vals):
                    return str(k)
        except Exception:
            pass
        return ""

    def _reap_write_faces(self, page, page_url: str, host: str) -> list:
        """Phase 241: observe the write requests the page emits for itself.

        Fills every named text control with a marker derived from the field
        name, clicks a deny-list-filtered bounded set of buttons, and keeps
        the requests whose BODY carries the marker.  Attribution is by
        marker presence (the socket.io/analytics traffic that also flows
        through has no marker), so what comes back is evidence, not a guess.

        Returns ``[{"method","url","field","encoding"}]``, same-origin only.
        """
        import json as _json
        from urllib.parse import urljoin, urlparse
        faces: list = []
        try:
            page.evaluate(_WRITE_FACE_LOGGER_JS)
        except Exception as e:
            _log.debug("dom: write-face logger install failed (%s)",
                       type(e).__name__, exc_info=True)
            return faces
        try:
            filled = page.evaluate(
                _WRITE_FACE_FILL_JS % _json.dumps(_WRITE_FACE_MARK))
        except Exception as e:
            _log.debug("dom: write-face fill failed (%s)",
                       type(e).__name__, exc_info=True)
            return faces
        if not filled:
            return faces
        try:
            clicked = page.evaluate(
                _WRITE_FACE_PICK_JS % _json.dumps(list(_WRITE_FACE_DENY)))
            page.wait_for_timeout(_WRITE_FACE_SETTLE_MS)
            if clicked:
                _log.debug("dom: write-face probe clicked %r on %s",
                           clicked, page_url)
        except Exception as e:
            _log.debug("dom: write-face interaction failed (%s)",
                       type(e).__name__, exc_info=True)
        try:
            log = page.evaluate("window.__wf_log || []") or []
        except Exception:
            log = []
        if not isinstance(log, list):
            return faces
        seen: set = set()
        for entry in log:
            if not isinstance(entry, dict):
                continue
            body = entry.get("body") or ""
            if _WRITE_FACE_MARK not in body:
                continue                     # not our write
            method = (entry.get("method") or "GET").upper()
            if method in ("GET", "HEAD", "OPTIONS"):
                continue                     # a read, not a write face
            try:
                abs_url = urljoin(page_url, entry.get("url") or "")
                p = urlparse(abs_url)
            except Exception:
                continue
            if p.scheme not in ("http", "https") or p.netloc.lower() != host:
                continue                     # same-origin rule (Phase 176l)
            field = self._marker_field(body, _WRITE_FACE_MARK)
            if not field:
                for name in filled:
                    if name and name in body:
                        field = name
                        break
            encoding = "json" if body.lstrip()[:1] in ("{", "[") else "form"
            key = (method, abs_url, field, encoding)
            if key in seen:
                continue
            seen.add(key)
            faces.append({"method": method, "url": abs_url, "field": field,
                          "encoding": encoding})
            if len(faces) >= _WRITE_FACE_MAX_FACES:
                break
        return faces

    def harvest(self, url: str, write_faces: bool = False) -> dict:
        """Phase 196: render ``url`` once and harvest the input face the
        RENDERED page exposes.

        Static mining guesses parameter names from a static wordlist; an
        SPA builds its forms and fires its API calls in the browser, where
        the static HTML never showed them.  One render yields:

          * ``names`` -- form/textarea/select/button field names of the
            live DOM, merged into the param-mining wordlist by the caller;
          * ``resource_urls`` -- the URLs the page itself fetched
            (``performance`` resource entries), same-origin filtered (the
            operator named this host; a third-party analytics call is
            someone else's system), deduped, capped -- SPA API endpoints
            nobody would have guessed.
          * ``routes`` -- hash routes the rendered page links to
            (``href="#/..."``).  The fragment is kept, because that is where
            the router reads its parameters from (Phase 210).

        Auth state (headers/cookies/localStorage) applies so authenticated
        pages render exactly as a victim sees them.  Best-effort: every
        failure degrades to an empty dict.
        """
        empty: dict = {"names": [], "resource_urls": [], "routes": []}
        if not self.available():
            return empty
        try:
            browser = get_shared_browser()
            page = browser.new_page(
                extra_http_headers=self.auth_headers or None)
        except Exception as e:
            # Phase 224: same never-silent rule as analyze() -- "no live
            # input face was harvested" and "the browser could not start"
            # must not look identical in the logs.
            _log.warning("dom: harvest could not open a page for %s "
                         "(%s: %s)", url, type(e).__name__, e)
            return empty
        try:
            if self.auth_cookies:
                try:
                    page.context.add_cookies(
                        _auth_cookie_dicts(self.auth_cookies, url))
                except Exception:
                    pass
            if self.auth_local_storage:
                try:
                    import json as _json
                    from urllib.parse import urlparse as _up
                    origin = "{0.scheme}://{0.netloc}".format(_up(url))
                    pairs = "; ".join(
                        "try { window.localStorage.setItem(%s, %s); "
                        "} catch (e) {}"
                        % (_json.dumps(k), _json.dumps(v))
                        for k, v in self.auth_local_storage.items())
                    page.add_init_script(
                        "if (location.origin === %s) { %s }"
                        % (_json.dumps(origin), pairs))
                except Exception:
                    pass
            try:
                page.goto(url, wait_until="commit",
                          timeout=int(self.timeout * 1000))
            except Exception:
                # Phase 200: same provisional-navigation trap as
                # _bounded_goto -- harvest's page.evaluate below would
                # otherwise block up to 763s (measured) on a page whose
                # navigation never committed.  A recovery to about:blank
                # costs 0.02s and the evaluate then honestly reports the
                # empty harvest (no render => no live input face).
                _recover_nav(page)
            try:
                page.wait_for_timeout(_DOM_SETTLE_MS)
            except Exception:
                pass
            try:
                raw = page.evaluate(r"""
(function(){
  var names = [];
  try {
    // Phase 241 fix: formcontrolname too.  Angular template-driven forms
    // bind controls by formcontrolname and often carry no name attribute
    // at all -- measured on Juice Shop (4 controls, 0 with name), where
    // the name-only selector made this harvest blind on a modern Material
    // app, which is exactly what it exists for.  ids are NOT collected:
    // mat-input-1 in a mining wordlist is noise.
    document.querySelectorAll(
      "input[name],textarea[name],select[name],button[name],"
      + "input[formcontrolname],textarea[formcontrolname],"
      + "select[formcontrolname],input[id],textarea[id],select[id]"
    ).forEach(function(e){
      var n = e.getAttribute("name") || e.getAttribute("formcontrolname");
      if (!n) {
        n = e.getAttribute("id") || '';
        // Framework-generated ids are noise in a mining wordlist.
        if (/^(mat|cdk|ng|input|elec)-/i.test(n)) return;
      }
      if (n) names.push(n);
    });
  } catch(e) {}
  var urls = [];
  try {
    (performance.getEntriesByType("resource") || []).forEach(function(r){
      if (r && r.name) urls.push(r.name);
    });
  } catch(e) {}
  var routes = [];
  try {
    document.querySelectorAll('a[href^="#/"]').forEach(function(a){
      var h = a.getAttribute("href");
      if (h) routes.push(h);
    });
  } catch(e) {}
  return {names: names, urls: urls, routes: routes};
})()
""")
            except Exception:
                return empty
            faces: list = []
            if write_faces:
                # Phase 241: opt-in (clicking real UI has side effects).
                from urllib.parse import urlparse as _up
                faces = self._reap_write_faces(
                    page, page.url, _up(url).netloc.lower())
        finally:
            try:
                page.close()
            except Exception:
                pass
        result = _normalize_harvest(raw, url)
        result["write_faces"] = faces
        return result

    @staticmethod
    def available() -> bool:
        try:
            import importlib.util as u
            return u.find_spec("playwright") is not None
        except Exception:
            return False

    def _probes(self, url: str, marker: str) -> list:
        """Build delivery probes: how to push the marker into each source.

        Covers the full set of DOM taint sources defined by OWASP:
          * location.hash / location.search / location.href / location.pathname
          * document.referrer (via Referer header injection)
          * document.cookie
          * window.name (cross-page persistence)
          * postMessage
        """
        from urllib.parse import urlparse, urlunparse, quote
        probes = []
        parsed = urlparse(url)
        base = url.split("#")[0].split("?")[0]
        # location.hash
        probes.append({"kind": "goto", "url": base + "#" + marker,
                       "source": "location.hash"})
        # location.search
        # NOTE: ``base`` has already been stripped of both the fragment and
        # the query, so the separator must be derived from ``base`` -- not
        # from the original ``url``.  Deriving it from ``url`` produced
        # ``http://h/p&__xss__=MK`` for every input that carried a query
        # string, i.e. a path with no query at all, which silently disabled
        # this probe on every URL a real scan visits.
        sep = "&" if "?" in base else "?"
        probes.append({"kind": "goto", "url": base + sep + "__xss__=" + marker,
                       "source": "location.search", "param": "__xss__"})
        # A page reads a *specific* parameter (``?q=``), so the generic
        # ``__xss__`` probe above only helps pages that read any parameter.
        # Replay the original query with each real parameter's value swapped
        # for the marker; capped so the browser cost stays bounded.
        for name in _query_param_names(url)[:_MAX_SEARCH_PARAM_PROBES]:
            if name == "__xss__":
                continue
            probes.append({"kind": "goto",
                           "url": _with_param_value(url, name, marker),
                           "source": "location.search",
                           "param": name})
        # SPA hash routing: the parameters live inside the fragment
        # (``#/search?q=``).  Nothing above reaches them -- ``base`` has the
        # fragment stripped, ``urlparse().query`` is empty, and an HTTP
        # request never carries the fragment at all.  The page's own router
        # is the only thing that ever sees these values, which is precisely
        # the DOM-XSS case.  Verified against OWASP Juice Shop, where both
        # hash-routed XSS went undetected without this probe.
        # Phase 213: the delivered KEY rides back on the finding
        # (``q@hash`` -- source-qualified, NOT a query parameter: no HTTP
        # request ever sees it, so report/poc/verify_fix must not treat it
        # as one).  Without it the report's param column was empty and the
        # fixer could not tell which key to escape.
        for name in _hash_param_names(url)[:_MAX_SEARCH_PARAM_PROBES]:
            probes.append({"kind": "goto",
                           "url": _with_hash_param_value(url, name, marker),
                           "source": "location.hash",
                           "param": name + "@hash"})
        # location.href (full URL reflected as-is)
        href_url = base + sep + "__xss__=" + quote(marker) + "#" + marker
        probes.append({"kind": "goto", "url": href_url,
                       "source": "location.href"})
        # location.pathname (path segment injected)
        path_marker = base.rstrip("/") + "/" + quote(marker, safe="")
        probes.append({"kind": "goto", "url": path_marker,
                       "source": "location.pathname"})
        # document.referrer (set via Referer header on navigation)
        origin = urlunparse((parsed.scheme, parsed.netloc, "", "", "", ""))
        probes.append({"kind": "referer", "url": url, "origin": origin,
                       "referer_value": href_url,
                       "source": "document.referrer"})
        # document.cookie
        probes.append({"kind": "cookie", "url": url, "origin": origin,
                       "source": "document.cookie"})
        # window.name (persists across navigations within the same tab)
        probes.append({"kind": "window_name", "url": url,
                       "source": "window.name"})
        # postMessage
        probes.append({"kind": "postmsg", "url": url, "source": "postMessage"})
        return probes

    def _bounded_goto(self, page, url: str, deadline: float) -> None:
        """Navigate with ``commit`` and a budget-capped timeout.

        Phase 148 fixed two unbounded-cost holes (see below).  Phase 155
        replaces the *wait shape* itself, on measurement:

          pos-sri-01 / pos-importmap-01 (pages loading cdn.example) cost
          32s each -- 27.2s of the 32.3s was inside ``page.goto``, only
          2.1s was the settle floor.  A classic ``<script src>`` blocks
          the parser, so DOMContentLoaded does not fire until that
          third-party resource resolves or fails; with a nav timeout of
          20s the 30s probe budget was spent after 2-3 probes, i.e. the
          page shape silently decided how many probes could run at all.

        ``commit`` returns as soon as the navigation commits.  The page's
        own scripts still execute (they run while parsing, which the
        existing per-probe settle covers -- this engine reads sink hits
        after that settle, not at navigation completion).  Measured on 25
        benchmark cases, domcontentloaded vs commit, same settle:

          * findings identical on all 25 (pos-dom-01..08 keep their
            dom_dynamic hits);
          * CDN-blocked families 31.6s -> 11.3s AND 2-3 probes -> all 8;
          * every other case unchanged (+-0.1s).

        Not waiting for DOMContentLoaded has one real consequence: an
        inline sink placed *after* a slow external script needs that
        script to resolve first, and we no longer wait for it.  That is
        the same trade the probe budget already makes (previously such a
        page consumed the whole budget and skipped its remaining
        probes); we take the bounded, uniform cost instead.

        IGNORED-PREMISE NOTE: "wait for readyState instead" was measured
        too (variant C: commit + readyState poll capped at 5s) and buys
        nothing -- readyState stays 'loading' for exactly as long as
        DOMContentLoaded was blocked: 27s, 6 probes.

        Phase 200 (measured, dev/_silent_nav_probe.py): when goto fails
        against a server that accepts the connection but never responds,
        Chromium's navigation stays PROVISIONAL and the NEXT
        ``page.evaluate`` blocks until the browser gives the navigation
        up -- **763s** in probe A (the sync-API thread parks inside
        Playwright's event loop; faulthandler shows only greenlet frames,
        which is why the field wedge looked like "no stack").  Recovery
        (probe B): navigating to ``about:blank`` commits in 0.02s and the
        evaluate then returns in 0.0s.  So a failed goto must NOT hand a
        half-navigated page to the caller -- this is the same unbounded
        cost Phase 148/155 were eliminating, just entering through the
        caller's evaluate instead of goto itself.
        """
        remaining = deadline - time.monotonic()
        timeout_ms = int(max(1.0, min(self.timeout, remaining)) * 1000)
        try:
            page.goto(url, wait_until="commit", timeout=timeout_ms)
        except Exception:
            # Recover BEFORE returning (see docstring).  Phase-141
            # compatibility: under wait_until="commit" a raised goto means
            # the target document never committed, so its scripts never
            # ran and there are no NEW sink hits to collect; hits from the
            # previous probe's document were already read unconditionally
            # at the end of that probe iteration (analyze reads
            # window.__xss_dom_hits after EVERY probe, including failed
            # ones).  Residual risk, accepted and bounded: a commit that
            # lands in the microseconds between the timeout raising and
            # this navigation would be discarded -- under the old code
            # that same page's evaluate did not run for 763s either, so
            # the recovery never converts a finding into a miss, it
            # converts a 763s stall into a 0.02s empty read.
            _recover_nav(page)

    def _try_carriers(self, page, probe: dict, marker: str, numtok: str,
                      dialog_msgs: list, deadline: float) -> tuple[bool, str]:
        """Replay ``probe``'s channel with executable carriers (Phase 226).

        Returns ``(executed, carrier_name)``.  ``executed`` is True only when
        a dialog carrying the numeric carrier token appeared while a carrier
        was in flight -- i.e. the PAGE's own code ran, because the
        instrumentation no longer fires dialogs of its own.  Absence of a
        dialog is a measured "not observed", never "impossible": the caller
        reports that as delivery evidence at a graded severity, not as an
        execution claim.

        Each carrier rides the SAME channel as the wave-0 probe (hash/query/
        cookie/referer/window.name/postMessage) so the replay differs from
        the original in exactly one variable: the payload shape.
        """
        kind = probe["kind"]
        for name, tpl in _CARRIER_SHAPES:
            carrier = tpl % int(numtok)
            if time.monotonic() > deadline:
                return False, ""
            start = len(dialog_msgs)
            try:
                if kind == "goto":
                    # Raw replacement (not quote()): the carrier must arrive
                    # the way an attacker's link would.  Query channels
                    # decode via URLSearchParams; fragment channels are
                    # percent-encoded by the browser itself, and that is
                    # the measured reality the verdict is allowed to see.
                    target = probe["url"].replace(marker, carrier)
                    # Phase 226 (measured on pos-dom-06): when only the
                    # FRAGMENT differs from the current URL, goto performs a
                    # same-document navigation -- the page's load-time code
                    # does NOT run again, so a `setTimeout(location.hash...)`
                    # page never sees the carrier and measures as not-fired
                    # although it is trivially exploitable.  Hop through
                    # about:blank when the non-fragment parts match, so the
                    # carrier always arrives with a full document load.
                    try:
                        same_doc = (page.url.split("#", 1)[0]
                                    == target.split("#", 1)[0])
                    except Exception:
                        same_doc = False
                    if same_doc:
                        self._bounded_goto(page, "about:blank", deadline)
                    self._bounded_goto(page, target, deadline)
                    page.wait_for_timeout(_DOM_SETTLE_MS)
                elif kind == "cookie":
                    page.context.add_cookies(
                        [{"name": "__xss__", "value": carrier,
                          "url": probe["origin"]}])
                    self._bounded_goto(page, probe["url"], deadline)
                    page.wait_for_timeout(_DOM_SETTLE_MS)
                elif kind == "referer":
                    hdrs = dict(self.auth_headers)
                    hdrs["Referer"] = probe["referer_value"].replace(marker, carrier)
                    page.context.set_extra_http_headers(hdrs)
                    try:
                        self._bounded_goto(page, probe["url"], deadline)
                        page.wait_for_timeout(_DOM_SETTLE_MS)
                    finally:
                        page.context.set_extra_http_headers(
                            dict(self.auth_headers))
                elif kind == "window_name":
                    self._bounded_goto(page, probe.get("origin")
                                       or probe["url"], deadline)
                    page.evaluate("window.__xss_dom_harness = 1;")
                    try:
                        page.evaluate("window.name = %s;" % json.dumps(carrier))
                    finally:
                        page.evaluate("window.__xss_dom_harness = 0;")
                    self._bounded_goto(page, probe["url"], deadline)
                    page.wait_for_timeout(_DOM_SETTLE_MS)
                elif kind == "postmsg":
                    # Fresh document (state from wave 0 is not reused), then
                    # re-dispatch every handler recorded by the init script
                    # with the carrier as the message data.  Origins are the
                    # same attacker-reachable pair the harness uses; the
                    # dispatching flag makes hits caused by this dispatch
                    # attributable to postMessage rather than to whichever
                    # probe happened to be running.
                    self._bounded_goto(page, probe["url"], deadline)
                    page.wait_for_timeout(200)
                    page.evaluate(
                        """(cm) => {
                             var O = ["https://attacker.example", "null"];
                             (window.__xss_dom_pm || []).forEach(function(h){
                               O.forEach(function(o){
                                 try {
                                   window.__xss_pm_dispatching = 1;
                                   h({data: cm, origin: o, source: null,
                                      isTrusted: true});
                                 } catch(e) {}
                                 finally { window.__xss_pm_dispatching = 0; }
                               });
                             });
                           }""", carrier)
                    page.wait_for_timeout(_DOM_SETTLE_MS)
                else:
                    return False, ""
            except Exception:
                _log.debug("dom: carrier %r skipped for %r probe",
                           name, kind, exc_info=True)
                continue
            if any(numtok in (m or "") for m in dialog_msgs[start:]):
                return True, name
        return False, ""

    def analyze(self, url: str, marker: str | None = None,
                dialog_token: str | None = None,
                click_selector: str | list | None = None,
                url_probes: bool = True) -> list:
        """Render ``url`` in the instrumented browser and report sink hits.

        ``dialog_token`` (Phase 194, stored-XSS closure): when set, a
        dialog whose message carries it counts as a hit -- the marker was
        embedded in the STORED PAYLOAD's own code, so ``alert('token')``
        firing proves the payload executed even when it flows through no
        instrumented sink (a pure ``<script>alert(...)</script>`` stored
        payload was invisible to the sink hooks).  This channel is for
        callers whose marker rides inside injected code ONLY: for URL
        source probes a page simply displaying the marker
        (``alert(location.hash)``) is not XSS, and claiming it would be an
        over-claim -- hence opt-in, never on by default.

        ``url_probes`` (Phase 283): set False when the CALLER already put the
        marker into the page (stored-XSS verification).  The engine then makes
        one plain navigation instead of pushing the marker into every URL
        source, so a hit can only have come from the page's own data -- the
        stored payload -- rather than from a reflected URL parameter.
        """
        if not self.available():
            return []
        marker = marker or (_stem_marker("xssentinel_dom_") + secrets.token_hex(4))
        # Phase 226: the decimal token carrier dialogs carry (see
        # _carrier_token).  Dialogs are attributed by EITHER token: the
        # string marker (a page alerting the value it received) or the
        # numeric carrier token (a carrier actually executing).
        numtok = _carrier_token(marker)
        findings: list = []
        seen: set = set()
        try:
            browser = get_shared_browser()
            # Phase 150: create the page carrying the authenticated
            # session.  extra_http_headers applies to every request the
            # page makes (document + XHR), which is how SPAs authenticate
            # API calls.  Domain-less auth cookies are pinned to the scan
            # URL's origin (Playwright requires url or domain+path).
            page = browser.new_page(
                extra_http_headers=self.auth_headers or None)
            if self.auth_local_storage:
                try:
                    import json as _json
                    from urllib.parse import urlparse as _up
                    origin = "{0.scheme}://{0.netloc}".format(_up(url))
                    pairs = "; ".join(
                        "try { window.localStorage.setItem(%s, %s); "
                        "} catch (e) {}"
                        % (_json.dumps(k), _json.dumps(v))
                        for k, v in self.auth_local_storage.items())
                    page.add_init_script(
                        "if (location.origin === %s) { %s }"
                        % (_json.dumps(origin), pairs))
                except Exception:
                    _log.debug("dom: auth localStorage seed failed (url=%s)",
                               url, exc_info=True)
            if self.auth_cookies:
                try:
                    page.context.add_cookies(
                        _auth_cookie_dicts(self.auth_cookies, url))
                except Exception:
                    _log.debug("dom: auth cookie apply failed (url=%s)",
                               url, exc_info=True)
            try:
                page.add_init_script(_init_script(marker))
                # Phase 194: record dialog messages while still dismissing
                # them (unhandled dialogs would stall the page).
                dialog_msgs: list[str] = []

                def _on_dialog(d):
                    try:
                        dialog_msgs.append(d.message)
                    except Exception:
                        pass
                    d.dismiss()

                page.on("dialog", _on_dialog)
                # Phase 147: bound the total cost of probing this url (see
                # _DOM_PROBE_BUDGET_S).  Findings are collected per probe, so
                # stopping early keeps everything already confirmed.
                deadline = time.monotonic() + _DOM_PROBE_BUDGET_S
                # Phase 226: dialog watermark for per-probe attribution, and
                # the carrier-wave counter (see _DOM_CARRIER_WAVE_MAX); the
                # PM carrier wave runs at most once per analyze() call.
                carrier_waves = 0
                pm_wave_done = False
                # Phase 282: a view that renders its stored value only
                # AFTER an interaction (a product-details dialog, a drawer,
                # an accordion row).  The click runs once, right after the
                # first navigation, so later probes observe the open state.
                clicked = False
                # Phase 283: the caller already put the marker in the page
                # (stored verification) -- do not ALSO push it into every URL
                # source.  Sharing one token with _probes() meant a view page
                # reflecting location.hash or a query parameter delivered that
                # token to a sink and the hit was attributed to the STORED
                # payload.  Measured on Juice Shop's API-only XSS: replaying
                # the finding's own payload showed the token never reaching
                # the page at all.  One plain navigation plus the interaction
                # dispatch is all a stored verification needs.
                if url_probes:
                    probes = self._probes(url, marker)
                else:
                    probes = [{"kind": "goto", "url": url,
                               "source": "stored_view"}]
                for probe in probes:
                    if time.monotonic() > deadline:
                        _log.debug(
                            "dom: probe budget %.0fs spent for %s -- stopping "
                            "with %d finding(s)",
                            _DOM_PROBE_BUDGET_S, url, len(findings))
                        break
                    dlg_start = len(dialog_msgs)
                    try:
                        if probe["kind"] == "goto":
                            # Phase 141: wait_until="load" (the old default)
                            # waits for every subresource.  A real page pulls
                            # CDN fonts and trackers, so on a slow or filtered
                            # network the navigation times out and the outer
                            # ``except: continue`` discards the probe WITHOUT
                            # ever reading the sink log -- the DOM engine looks
                            # like it found nothing while it never actually
                            # looked.  A navigation error must not skip the hit
                            # log either: the sink can fire before a late
                            # subresource trips the timeout.
                            # Phase 155: the wait is now "commit" (see
                            # _bounded_goto) -- even domcontentloaded can be
                            # blocked indefinitely by one third-party script.
                            self._bounded_goto(page, probe["url"], deadline)
                            # Let the route render (see _DOM_SETTLE_MS).
                            page.wait_for_timeout(_DOM_SETTLE_MS)
                            if click_selector and not clicked:
                                clicked = True
                                # Phase 284: a LIST of selectors is clicked
                                # IN ORDER.  Paginated views need this: a
                                # stored row that is not on the first page is
                                # invisible, and "Next page" must be clicked
                                # N times to reach it (measured on Juice
                                # Shop's admin feedback table, 10 rows/page).
                                selectors = (click_selector
                                             if isinstance(click_selector, list)
                                             else [click_selector])
                                for sel in selectors:
                                    try:
                                        # Phase 282: click the FIRST match.  A
                                        # selector like `mat-card` matches
                                        # every result card, and Playwright's
                                        # strict mode then refuses the click
                                        # outright -- the view never opens and
                                        # the stored value is never rendered.
                                        # Measured on Juice Shop's search page
                                        # (15 cards).
                                        page.locator(sel).first.click(
                                            timeout=5000)
                                        page.wait_for_timeout(_DOM_SETTLE_MS)
                                    except Exception:
                                        # Phase 284: a click that cannot be
                                        # performed (a consent overlay makes
                                        # Playwright's actionability check
                                        # time out -- measured on the search
                                        # page, #5, and on the admin feedback
                                        # table, #7) is reported and the
                                        # remaining selectors are skipped.
                                        # Deliberately NOT fallen back to
                                        # dispatch_event: that would make the
                                        # click "succeed" without the app
                                        # ever seeing the interaction, and a
                                        # silent fake success is worse than a
                                        # visible miss.
                                        _log.debug("dom: view click %r failed",
                                                   sel)
                                        break
                        elif probe["kind"] == "cookie":
                            page.context.add_cookies(
                                [{"name": "__xss__", "value": marker,
                                  "url": probe["origin"]}])
                            self._bounded_goto(page, probe["url"], deadline)
                            page.wait_for_timeout(_DOM_SETTLE_MS)
                        elif probe["kind"] == "postmsg":
                            self._bounded_goto(page, probe["url"], deadline)
                            page.wait_for_timeout(400)
                        elif probe["kind"] == "referer":
                            # Inject a forged Referer header on the navigation
                            # so ``document.referrer`` picks up the marker.
                            # Phase 150: set_extra_http_headers REPLACES the
                            # whole dict -- resetting to {} would silently
                            # strip the authenticated session's headers from
                            # every later probe, so always merge with them.
                            try:
                                hdrs = dict(self.auth_headers)
                                hdrs["Referer"] = probe["referer_value"]
                                page.context.set_extra_http_headers(hdrs)
                            except Exception:
                                pass
                            self._bounded_goto(page, probe["url"], deadline)
                            page.wait_for_timeout(_DOM_SETTLE_MS)
                            try:
                                page.context.set_extra_http_headers(
                                    dict(self.auth_headers))
                            except Exception:
                                pass
                        elif probe["kind"] == "window_name":
                            # window.name persists across navigations within
                            # the same tab.  Set it via an intermediate page
                            # on the target origin, then navigate to the URL.
                            #
                            # Phase 162: this read ``probe["origin"]``
                            # unconditionally, but _probes() builds the
                            # window_name probe WITHOUT that key, so it raised
                            # KeyError, the surrounding ``except Exception:
                            # continue`` swallowed it, and the probe never
                            # navigated once.  Measured on a page whose only
                            # sink is ``innerHTML = window.name``: zero
                            # navigations, no finding -- a whole advertised
                            # probe kind that had never run.  ``.get`` keeps a
                            # future probe shape from costing a silent skip.
                            self._bounded_goto(page, probe.get("origin")
                                               or probe["url"], deadline)
                            try:
                                # Phase 162: the eval hook must not treat the
                                # marker WE inject here as a page-initiated
                                # eval -- it did, and two SAFE cases scored as
                                # "DOM XSS CONFIRMED" (diagnosed from the
                                # finding's payload field, which was this very
                                # source string).
                                #
                                # The flag has to be raised in its OWN
                                # evaluation: the hook runs when eval is
                                # CALLED, i.e. before the evaluated body
                                # executes, so setting it inside the same
                                # expression is too late.  Cleared right after,
                                # before the reload, so the page's own eval of
                                # window.name is still detected.
                                page.evaluate("window.__xss_dom_harness = 1;")
                                try:
                                    page.evaluate("window.name = %s;"
                                                  % json.dumps(marker))
                                finally:
                                    page.evaluate(
                                        "window.__xss_dom_harness = 0;")
                                self._bounded_goto(page, probe["url"],
                                                   deadline)
                                page.wait_for_timeout(_DOM_SETTLE_MS)
                            except Exception:
                                continue
                    except Exception:
                        # Phase 162: a probe that raises is skipped, which is
                        # right (one bad probe must not kill the scan) but was
                        # INVISIBLE -- that is exactly how the window_name
                        # KeyError above went unnoticed for so long.  Log it.
                        _log.debug("dom: probe %r skipped for %s",
                                   probe.get("kind"), url, exc_info=True)
                        continue
                    # Phase 193: synthetic interaction dispatch.  Reflected
                    # requires-interaction handlers (onpointerdown/onclick/...)
                    # are live attributes the moment the page renders; the
                    # only missing ingredient is the interaction.  Dispatch
                    # the bounded event set on marker-bearing elements, then
                    # re-read the sink log -- hits carry via='interaction'.
                    # Phase 193 (measured, the hard way): the dispatch JS
                    # itself CONTAINS the marker (the NEEDLE line), so the
                    # eval hook would record the dispatch source as a
                    # page-initiated eval on EVERY page -- a dozen strict-gate
                    # FPs.  Raise the Phase-162 harness flag around it, same
                    # contract as the window_name probe below.
                    try:
                        page.evaluate("window.__xss_dom_harness = 1;")
                        try:
                            page.evaluate(interaction_dispatch_js(marker))
                            page.wait_for_timeout(200)
                        finally:
                            page.evaluate("window.__xss_dom_harness = 0;")
                    except Exception:
                        pass
                    try:
                        hits = page.evaluate("window.__xss_dom_hits || []")
                    except Exception:
                        hits = []
                    # Phase 194: the dialog channel as a FALLBACK -- when no
                    # instrumented sink saw the marker but a dialog carried
                    # the stored payload's token, the payload executed.
                    # Fallback-only: sink hits name the specific sink and
                    # are the stronger, more specific evidence.
                    if not hits and dialog_token:
                        _tok = [m for m in dialog_msgs
                                if dialog_token in (m or "")]
                        if _tok:
                            hits.append({"sink": "dialog",
                                         "snippet": _tok[0][:200],
                                         "via": "dialog"})
                    # Phase 226: execution tier.  A dialog carrying either
                    # token that fired during THIS probe's slice means the
                    # page's own code ran it (the instrumentation no longer
                    # alerts).  Otherwise the channel is replayed with
                    # executable carriers -- and only a dialog fired by the
                    # page during that replay earns "browser-executed".
                    executed = any(
                        marker in (m or "") or numtok in (m or "")
                        for m in dialog_msgs[dlg_start:])
                    carrier_used = ""
                    # Phase 226: hits caused by the init script's own
                    # postMessage delivery carry via='postmsg' -- they are
                    # postMessage evidence no matter which probe's document
                    # they landed on (the dispatch fires on EVERY document
                    # load, which used to misattribute them to whatever
                    # source probe was running).  One PM carrier wave per
                    # analyze() call answers for all of them.
                    pm_hits = [h for h in hits if h.get("via") == "postmsg"]
                    other_hits = [h for h in hits if h.get("via") != "postmsg"]
                    pm_executed, pm_carrier_used = False, ""
                    if (pm_hits and not pm_wave_done and not executed
                            and carrier_waves < _DOM_CARRIER_WAVE_MAX
                            and time.monotonic() <= deadline):
                        pm_wave_done = True
                        carrier_waves += 1
                        pm_executed, pm_carrier_used = self._try_carriers(
                            page, {"kind": "postmsg", "url": url,
                                   "source": "postMessage"},
                            marker, numtok, dialog_msgs, deadline)
                    if (other_hits and not executed
                            and not any(h.get("via") == "dialog"
                                        for h in other_hits)
                            and carrier_waves < _DOM_CARRIER_WAVE_MAX
                            and time.monotonic() <= deadline):
                        carrier_waves += 1
                        executed, carrier_used = self._try_carriers(
                            page, probe, marker, numtok, dialog_msgs, deadline)
                    elif any(h.get("via") == "dialog" for h in hits):
                        # Stored-payload token channel: the dialog IS the
                        # execution (Phase 194), no replay needed.
                        executed = True
                    for h in hits:
                        sink = h.get("sink")
                        _pm = h.get("via") == "postmsg"
                        src = "postMessage" if _pm else probe["source"]
                        key = (sink, src)
                        if key in seen:
                            continue
                        seen.add(key)
                        _exec = bool(executed
                                     or (_pm and pm_executed)
                                     or h.get("via") == "dialog")
                        _carrier = (pm_carrier_used if _pm else carrier_used) \
                            if _exec else ""
                        if _exec:
                            detail = (
                                f"DOM XSS CONFIRMED in real browser: "
                                f"attacker-controlled source "
                                f"'{src}' reached executable "
                                f"sink '{sink}' and the page's own handler "
                                f"fired alert(marker)"
                                + (f" (carrier: {_carrier})"
                                   if _carrier else "") + ".")
                        else:
                            # Plain reachability: the marker arrived but no
                            # execution was observed for any carrier shape.
                            # Report as delivery evidence; the grading in
                            # scanner_layers turns this into a low-severity
                            # browser-refuted finding, NEVER a high claim
                            # (Phase 226; measured on range6's safe twin,
                            # where the old wording claimed "marker executed"
                            # for inert text).
                            detail = (
                                f"Attacker-controlled source "
                                f"'{src}' reached sink "
                                f"'{sink}', but no execution was observed "
                                f"in this browser (carrier shapes tried: "
                                f"{', '.join(name for name, _ in _CARRIER_SHAPES)}). "
                                f"Delivery evidence only -- "
                                f"not proof of absence.")
                        findings.append({
                            "type": "dom_dynamic",
                            "sink": sink,
                            "source": src,
                            # Phase 213: the delivered key (``q`` / ``q@hash``
                            # / ``__xss__``), or None when the probe had no
                            # key position (raw fragment, pathname, cookie...).
                            # PM-attributed hits have no key position either.
                            "param": None if _pm else probe.get("param"),
                            "snippet": h.get("snippet", ""),
                            "confidence": "high" if _exec else "medium",
                            # Phase 226: the tier the wrappers grade by.
                            "executed": _exec,
                            "carrier": _carrier,
                            "detail": detail,
                        })
                        if src == "postMessage":
                            findings[-1]["detail"] += (
                                " Message delivered with an ATTACKER origin "
                                "(https://attacker.example / sandboxed null) "
                                "and still reached the sink, so origin "
                                "validation is absent or ineffective.")
                        if h.get("via") == "interaction":
                            findings[-1]["detail"] += (
                                " Sink fired after synthetic interaction "
                                "events were dispatched on the injected "
                                "element (requires-interaction handler).")
            finally:
                # Pages are disposable; the shared browser is NOT closed.
                try:
                    page.close()
                except Exception:
                    pass
        except Exception as e:
            # Phase 224: this used to be a bare `return []`, which made
            # "the browser could not run at all" (stale shared instance,
            # failed launch, host pressure) indistinguishable from "the
            # page is clean" -- the exact shape that hid the range5
            # live-pair failure as `all findings: []` for a whole 13h
            # suite run.  A whole capability being unavailable is not a
            # best-effort detail: warn with the reason.
            _log.warning("dom: browser analysis failed for %s (%s: %s) -- "
                         "dynamic DOM confirmation unavailable for this "
                         "call", url, type(e).__name__, e, exc_info=True)
            return []
        return findings
