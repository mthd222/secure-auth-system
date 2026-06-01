document.querySelectorAll(".password-toggle").forEach((button) => {
    button.addEventListener("click", () => {
        const targetId = button.dataset.target;
        const passwordField = document.getElementById(targetId);

        if (!passwordField) {
            return;
        }

        if (passwordField.type === "password") {
            passwordField.type = "text";
            button.textContent = "Hide";
            return;
        }

        passwordField.type = "password";
        button.textContent = "Show";
    });
});
