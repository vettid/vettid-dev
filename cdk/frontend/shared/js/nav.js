(function() {
  'use strict';

  var toggle = document.querySelector('.nav-toggle');
  var navMenu = document.getElementById('navMenu');
  var overlay = document.querySelector('.nav-overlay');

  if (!toggle || !navMenu) {
    return;
  }

  var isOpen = false;

  function openMenu() {
    isOpen = true;
    toggle.classList.add('active');
    navMenu.style.display = 'flex';
    if (overlay) {
      overlay.style.display = 'block';
    }
    toggle.setAttribute('aria-expanded', 'true');
    document.body.style.overflow = 'hidden';
  }

  function closeMenu() {
    isOpen = false;
    toggle.classList.remove('active');
    navMenu.style.display = 'none';
    if (overlay) {
      overlay.style.display = 'none';
    }
    toggle.setAttribute('aria-expanded', 'false');
    document.body.style.overflow = '';
  }

  toggle.addEventListener('click', function(e) {
    e.preventDefault();
    e.stopPropagation();
    if (isOpen) {
      closeMenu();
    } else {
      openMenu();
    }
  });

  if (overlay) {
    overlay.addEventListener('click', function(e) {
      e.preventDefault();
      closeMenu();
    });
  }

  document.addEventListener('keydown', function(e) {
    if (e.key === 'Escape' && isOpen) {
      closeMenu();
    }
  });
})();
