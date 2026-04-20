const form = document.getElementById("login-form");
const messageEl = document.getElementById("message");

if (localStorage.getItem("token")) {
  window.location.href = "./profile.html";
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  setMessage(messageEl, "", "");

  const email = document.getElementById("email").value.trim();
  const password = document.getElementById("password").value;

  try {
    const result = await apiRequest("/login", {
      method: "POST",
      body: JSON.stringify({ email, password }),
    });

    localStorage.setItem("token", result.token);
    setMessage(messageEl, "Успешный вход. Переходим в профиль...", "success");

    setTimeout(() => {
      window.location.href = "./profile.html";
    }, 500);
  } catch (error) {
    setMessage(messageEl, error.message, "error");
  }
});
