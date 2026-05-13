async function loadPartial(target) {
    const src = target.getAttribute('data-partial');
    if (!src) return;
    const response = await fetch(src);
    if (!response.ok) throw new Error(`failed to load partial: ${src}`);
    target.innerHTML = await response.text();
}

document.addEventListener('DOMContentLoaded', () => {
    for (const target of document.querySelectorAll('[data-partial], [data-include]')) {
        if (!target.hasAttribute('data-partial')) {
            target.setAttribute('data-partial', target.getAttribute('data-include') || '');
        }
        loadPartial(target).catch((error) => {
            console.error(error);
        });
    }
});
