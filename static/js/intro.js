'use strict';

(function () {
  var intro = document.getElementById('intro');
  if (!intro) return;

  var KEY = 'tv-intro-seen';
  var scenes = intro.querySelectorAll('.scene');
  var bars = intro.querySelectorAll('.intro-progress span');
  var yearEl = document.getElementById('introYear');
  var reduced = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  var index = -1, timer = null, lastFocus = null;

  function seen() { try { return localStorage.getItem(KEY) === '1'; } catch (e) { return false; } }
  function markSeen() { try { localStorage.setItem(KEY, '1'); } catch (e) {} }

  function countUp(el) {
    var target = +el.getAttribute('data-count');
    var suffix = el.getAttribute('data-suffix') || '';
    if (reduced) { el.textContent = target + suffix; return; }
    var start = null, dur = 1400;
    function step(t) {
      if (!start) start = t;
      var p = Math.min((t - start) / dur, 1);
      var eased = 1 - Math.pow(1 - p, 3);
      el.textContent = Math.round(target * eased) + (p === 1 ? suffix : '');
      if (p < 1) requestAnimationFrame(step);
    }
    requestAnimationFrame(step);
  }

  function animateBar(i, ms) {
    bars.forEach(function (b, j) {
      var fill = b.querySelector('i');
      fill.style.transition = 'none';
      if (j < i) { b.classList.add('done'); fill.style.width = ''; }
      else { b.classList.remove('done'); fill.style.width = '0'; }
    });
    var cur = bars[i] && bars[i].querySelector('i');
    if (!cur) return;
    if (!ms) { cur.style.width = '100%'; return; }
    void cur.offsetWidth;
    cur.style.transition = 'width ' + ms + 'ms linear';
    cur.style.width = '100%';
  }

  function go(i) {
    if (i < 0 || i >= scenes.length) return;
    clearTimeout(timer);
    if (scenes[index]) scenes[index].classList.remove('active');
    index = i;
    var scene = scenes[i];
    scene.classList.add('active');
    yearEl.textContent = scene.getAttribute('data-year') || '';
    scene.querySelectorAll('[data-count]').forEach(countUp);
    var ms = +scene.getAttribute('data-ms') || 0;
    animateBar(i, reduced ? 0 : ms);
    if (ms && !reduced) timer = setTimeout(function () { go(i + 1); }, ms);
    if (i === scenes.length - 1) document.getElementById('introEnter').focus();
  }

  function open() {
    lastFocus = document.activeElement;
    intro.hidden = false;
    document.body.classList.add('intro-open');
    requestAnimationFrame(function () { intro.classList.add('show'); });
    document.getElementById('introSkip').focus();
    go(0);
  }

  function close() {
    clearTimeout(timer);
    markSeen();
    intro.classList.remove('show');
    document.body.classList.remove('intro-open');
    setTimeout(function () {
      intro.hidden = true;
      if (scenes[index]) scenes[index].classList.remove('active');
      index = -1;
      if (lastFocus && lastFocus.focus) lastFocus.focus();
    }, 600);
  }

  document.getElementById('introSkip').addEventListener('click', close);
  document.getElementById('introEnter').addEventListener('click', close);

  intro.addEventListener('keydown', function (e) {
    if (e.key === 'Escape') close();
    else if (e.key === 'ArrowRight') go(index + 1);
    else if (e.key === 'ArrowLeft') go(index - 1);
    else if (e.key === 'Tab') {
      // keep focus inside the dialog
      var f = intro.querySelectorAll('button');
      var visible = Array.prototype.filter.call(f, function (b) { return b.offsetParent !== null; });
      if (!visible.length) return;
      var first = visible[0], last = visible[visible.length - 1];
      if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); }
      else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
    }
  });

  document.querySelectorAll('[data-intro-replay]').forEach(function (b) {
    b.addEventListener('click', open);
  });

  if (!seen() && !reduced) open();
})();
