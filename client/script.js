const API = "http://localhost:8080";
let token = "";
let userId = null;

document.getElementById("register-form").onsubmit = async e => {
  e.preventDefault();
  const data = Object.fromEntries(new FormData(e.target).entries());

  const res = await fetch(`${API}/register/`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(data),
  });

  alert(res.ok ? "Успешно зарегистрирован!" : "Ошибка регистрации");
};

document.getElementById("login-form").onsubmit = async e => {
  e.preventDefault();
  const data = Object.fromEntries(new FormData(e.target).entries());

  const res = await fetch(`${API}/login/`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(data),
  });

  if (res.ok) {
    const result = await res.json();
    token = result.access_token;
    await loadUser();
  } else {
    alert("Неверные данные");
  }
};

async function loadUser() {
  const res = await fetch(`${API}/me`, {
    headers: { Authorization: `Bearer ${token}` }
  });

  if (res.ok) {
    const user = await res.json();
    userId = user.id;
    document.getElementById("user-name").textContent = user.username;
    document.getElementById("auth").style.display = "none";
    document.getElementById("dashboard").style.display = "block";

    loadRecommendations();
    loadReport();
  }
}

document.getElementById("logout").onclick = () => {
  token = "";
  location.reload();
};

document.getElementById("health-form").onsubmit = async e => {
  e.preventDefault();
  const data = Object.fromEntries(new FormData(e.target).entries());
  data.timestamp = new Date().toISOString();

  const res = await fetch(`${API}/users/${userId}/health`, {
    method: "POST",
    headers: {
      "Authorization": `Bearer ${token}`,
      "Content-Type": "application/json"
    },
    body: JSON.stringify(data),
  });

  alert(res.ok ? "Данные сохранены" : "Ошибка сохранения");
};

async function loadRecommendations() {
  const res = await fetch(`${API}/users/${userId}/recommendations`, {
    headers: { Authorization: `Bearer ${token}` }
  });

  const data = await res.json();
  const list = document.getElementById("recommendations");
  list.innerHTML = "";
  data.recommendations.forEach(r => {
    const li = document.createElement("li");
    li.textContent = r;
    list.appendChild(li);
  });
}

async function loadReport() {
  const res = await fetch(`${API}/users/${userId}/report`, {
    headers: { Authorization: `Bearer ${token}` }
  });

  const data = await res.json();
  document.getElementById("report").textContent = JSON.stringify(data, null, 2);
}

document.getElementById("load-chart").onclick = async () => {
  const metric = document.getElementById("metric-select").value;

  const res = await fetch(`${API}/users/${userId}/charts/${metric}`, {
    headers: {
      "Authorization": `Bearer ${token}`
    }
  });

  if (res.ok) {
    const blob = await res.blob();
    const imageUrl = URL.createObjectURL(blob);
    document.getElementById("chart").src = imageUrl;
  } else {
    alert("Ошибка при загрузке графика");
  }
};

document.getElementById("show-register-form").onclick = () => {
  document.getElementById("register-form-container").style.display = "block";
};
