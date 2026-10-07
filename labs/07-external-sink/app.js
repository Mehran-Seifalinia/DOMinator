var params = new URLSearchParams(location.search);
var target = document.getElementById('sink');

if (target) {
    target.innerHTML = params.get('q') || '';
}

window.addEventListener('load', function () {
    sessionStorage.setItem('lab', '07');
});
