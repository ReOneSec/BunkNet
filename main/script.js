

/**
 * BunkNet Landing Page Script
 * Handles:
 * 1. Mobile navigation menu toggle.
 * 2. Fade-in animations on scroll.
 */

document.addEventListener('DOMContentLoaded', () => {
    // --- Mobile Menu Toggle ---
    const mobileNavToggle = document.querySelector('.mobile-nav-toggle');
    const mobileNav = document.querySelector('.main-nav-mobile');

    if (mobileNavToggle && mobileNav) {
        mobileNavToggle.addEventListener('click', () => {
            mobileNav.classList.toggle('hidden');
            const icon = mobileNavToggle.querySelector('i');
            icon.classList.toggle('fa-bars');
            icon.classList.toggle('fa-xmark');
        });
    }

    // --- Scroll-triggered animations ---
    const sections = document.querySelectorAll('.fade-in-section');
    
    const observer = new IntersectionObserver(entries => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                entry.target.classList.add('is-visible');
                // Optional: stop observing the element once it's visible
                observer.unobserve(entry.target);
            }
        });
    }, {
        // Start the animation when the element is 10% in view
        threshold: 0.1
    });

    sections.forEach(section => {
        observer.observe(section);
    });
});
