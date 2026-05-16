function togglePassword(passwordId, iconId){

    let passwordField =
        document.getElementById(passwordId);

    let icon =
        document.getElementById(iconId);

    if(passwordField.type === "password"){

        passwordField.type = "text";

        icon.classList.remove("fa-eye");
        icon.classList.add("fa-eye-slash");
    }

    else{

        passwordField.type = "password";

        icon.classList.remove("fa-eye-slash");
        icon.classList.add("fa-eye");
    }
}