/* filepath: c:\Users\kotha\OneDrive\Documents\GitHub\ISAA-Project-1\static\script.js */
document.addEventListener("DOMContentLoaded", function() {
    const images = [
        'url("/static/images/background1.jpg")',
        'url("/static/images/background2.jpg")',
        'url("/static/images/background3.jpg")'
    ];

    const randomImage = images[Math.floor(Math.random() * images.length)];
    document.body.style.backgroundImage = randomImage;
});