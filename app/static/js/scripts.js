// scripts.js

document.addEventListener('DOMContentLoaded', () => {
    console.log('Teamsphee UI Loaded');

    // 1. ✨ Auto-dismiss alerts with fade effect
    const alerts = document.querySelectorAll('.alert');
    alerts.forEach(alert => {
        alert.style.opacity = '1';
        setTimeout(() => {
            alert.style.transition = 'opacity 0.5s ease-out';
            alert.style.opacity = '0';
            setTimeout(() => alert.remove(), 500);
        }, 3000);
    });

    // 2. 🚀 Add a loading state to all submit buttons
    const forms = document.querySelectorAll('form');
    forms.forEach(form => {
        form.addEventListener('submit', (e) => {
            const submitBtn = form.querySelector('button[type="submit"]');
            if (submitBtn) {
                submitBtn.disabled = true;
                const original = submitBtn.innerHTML;
                submitBtn.innerHTML = `<span class="spinner-border spinner-border-sm me-2" role="status" aria-hidden="true"></span>Working...`;
                setTimeout(() => {
                    submitBtn.disabled = false;
                    submitBtn.innerHTML = original;
                }, 5000); // fallback restore
            }
        });
    });

    // 3. 🎯 Highlight active nav links
    const currentPath = window.location.pathname;
    const navLinks = document.querySelectorAll('.nav-link');
    navLinks.forEach(link => {
        if (link.getAttribute('href') === currentPath) {
            link.classList.add('active');
        }
    });

    // 4. 🎨 Improve comment input UX
    const commentInputs = document.querySelectorAll('form[action*="comment"] input[name="content"]');
    commentInputs.forEach(input => {
        input.placeholder = '💬 Write a comment...';
        input.addEventListener('focus', () => {
            input.style.borderColor = '#007bff';
            input.style.boxShadow = '0 0 5px rgba(0,123,255,0.2)';
        });
        input.addEventListener('blur', () => {
            input.style.borderColor = '#ccc';
            input.style.boxShadow = 'none';
        });
    });

    // 5. 🧹 Add simple hover effect to tasks (already supported via CSS, just in case)
    const taskCards = document.querySelectorAll('ul li');
    taskCards.forEach(card => {
        card.addEventListener('mouseenter', () => {
            card.style.boxShadow = '0 4px 12px rgba(0,0,0,0.07)';
        });
        card.addEventListener('mouseleave', () => {
            card.style.boxShadow = '0 2px 6px rgba(0,0,0,0.03)';
        });
    });
});
