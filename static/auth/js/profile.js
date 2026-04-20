const emailEl = document.getElementById("email-value");
const messageEl = document.getElementById("message");
const logoutBtn = document.getElementById("logout-btn");

const token = localStorage.getItem("token");
if (!token) {
  window.location.href = "./index.html";
}

async function loadProfile() {
  try {
    const result = await apiRequest("/profile", {
      method: "GET",
      headers: {
        Authorization: `Bearer ${token}`,
      },
    });

    emailEl.textContent = result.user.email;
  } catch (error) {
    setMessage(messageEl, error.message, "error");
    localStorage.removeItem("token");
    setTimeout(() => {
      window.location.href = "./index.html";
    }, 900);
  }
}

logoutBtn.addEventListener("click", () => {
  localStorage.removeItem("token");
  window.location.href = "./index.html";
});

loadProfile();
