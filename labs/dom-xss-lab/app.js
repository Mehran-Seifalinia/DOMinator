function renderFromHash() {
    var target = document.getElementById("hash-sink");
    if (target) {
        target.innerHTML = decodeURIComponent(window.location.hash.slice(1));
    }
}

function loadStatus() {
    fetch("/status.json")
        .then(function (response) { return response.json(); })
        .then(function (data) {
            var node = document.getElementById("query-sink");
            if (node && data.status) {
                node.insertAdjacentHTML("beforeend", "<em>" + data.status + "</em>");
            }
        })
        .catch(function () { return undefined; });
}

document.addEventListener("DOMContentLoaded", function () {
    renderFromHash();
    loadStatus();
    sessionStorage.setItem("lab", "loaded");
    window.name = location.pathname;
});
