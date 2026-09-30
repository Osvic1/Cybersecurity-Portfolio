'use strict';

(function () {
  var root = document.documentElement;

  // Theme
  var themeBtn = document.getElementById('themeToggle');
  if (themeBtn) {
    themeBtn.addEventListener('click', function () {
      var next = root.getAttribute('data-theme') === 'light' ? 'dark' : 'light';
      root.setAttribute('data-theme', next);
      try { localStorage.setItem('theme', next); } catch (e) {}
    });
  }

  // Mobile menu
  var menuBtn = document.getElementById('menuBtn');
  var links = document.getElementById('navLinks');
  if (menuBtn && links) {
    menuBtn.addEventListener('click', function () {
      var open = links.classList.toggle('open');
      menuBtn.setAttribute('aria-expanded', String(open));
      menuBtn.setAttribute('aria-label', open ? 'Close menu' : 'Open menu');
    });
  }

  // Nav border + back-to-top
  var nav = document.getElementById('nav');
  var toTop = document.getElementById('toTop');
  function onScroll() {
    var y = window.scrollY;
    if (nav) nav.classList.toggle('scrolled', y > 8);
    if (toTop) toTop.classList.toggle('show', y > 600);
  }
  window.addEventListener('scroll', onScroll, { passive: true });
  onScroll();
  if (toTop) toTop.addEventListener('click', function () { window.scrollTo({ top: 0, behavior: 'smooth' }); });

  // Flash messages
  document.querySelectorAll('.flash').forEach(function (el) {
    function close() { el.style.transition = 'opacity .3s'; el.style.opacity = '0'; setTimeout(function () { el.remove(); }, 300); }
    var t = setTimeout(close, 6000);
    el.querySelector('button').addEventListener('click', function () { clearTimeout(t); close(); });
  });

  // Reveal on scroll
  var items = document.querySelectorAll('.reveal');
  if ('IntersectionObserver' in window) {
    var io = new IntersectionObserver(function (entries) {
      entries.forEach(function (e) {
        if (e.isIntersecting) { e.target.classList.add('in'); io.unobserve(e.target); }
      });
    }, { rootMargin: '0px 0px -8% 0px', threshold: 0.08 });
    items.forEach(function (el) { io.observe(el); });
  } else {
    items.forEach(function (el) { el.classList.add('in'); });
  }

  // Screenshot carousels
  document.querySelectorAll('[data-slides]').forEach(function (wrap) {
    var slides = wrap.querySelectorAll('img');
    var dots = wrap.querySelectorAll('.slide-dots span');
    if (slides.length < 2) return;
    if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) return;
    var i = 0;
    setInterval(function () {
      slides[i].style.opacity = '0'; slides[i].classList.remove('is-active');
      if (dots[i]) dots[i].classList.remove('is-active');
      i = (i + 1) % slides.length;
      slides[i].style.opacity = '1'; slides[i].classList.add('is-active');
      if (dots[i]) dots[i].classList.add('is-active');
    }, 3800);
  });
})();
