// main.js — Timothy Victor Portfolio
// All event listeners use passive where applicable for performance

'use strict';

// ── Smooth scroll for anchor links ──────────────────────────────────────────
document.querySelectorAll('a[href^="#"]').forEach(anchor => {
  anchor.addEventListener('click', function(e) {
    const target = document.querySelector(this.getAttribute('href'));
    if (target) {
      e.preventDefault();
      target.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }
  });
});

// ── Scroll-to-top button (dynamically added) ─────────────────────────────────
(function(){
  const btn = document.createElement('button');
  btn.innerHTML = '<i class="fas fa-chevron-up"></i>';
  btn.setAttribute('aria-label', 'Scroll to top');
  btn.style.cssText = `
    position:fixed; bottom:2rem; right:2rem; z-index:999;
    width:42px; height:42px; border-radius:50%;
    background:rgba(0,255,136,0.15); border:1px solid rgba(0,255,136,0.4);
    color:#00ff88; cursor:pointer; font-size:0.9rem;
    display:none; align-items:center; justify-content:center;
    transition:opacity 0.3s, background 0.2s;
  `;
  btn.addEventListener('click', () => window.scrollTo({ top: 0, behavior: 'smooth' }));
  btn.addEventListener('mouseover', () => btn.style.background = 'rgba(0,255,136,0.3)');
  btn.addEventListener('mouseout',  () => btn.style.background = 'rgba(0,255,136,0.15)');
  document.body.appendChild(btn);

  window.addEventListener('scroll', () => {
    btn.style.display = window.scrollY > 400 ? 'flex' : 'none';
  }, { passive: true });
})();
