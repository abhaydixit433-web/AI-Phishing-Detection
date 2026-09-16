const form = document.querySelector("form");

form.addEventListener("submit", () => {

    const btn = document.querySelector("button");

    btn.innerHTML = "Checking...";

    btn.disabled = true;

});