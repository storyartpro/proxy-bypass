const state = {
  status: null,
  proxies: [],
  blocked: [],
  servers: [],
  editingId: null,
};

const $ = (id) => document.getElementById(id);

function toast(message, isError = false) {
  const el = $("toast");
  el.textContent = message;
  el.className = `toast show${isError ? " error" : ""}`;
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => (el.className = "toast"), 3500);
}

async function api(path, body) {
  const options = body === undefined ? {} : { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) };
  const response = await fetch(path, options);
  const data = await response.json().catch(() => ({}));
  if (!response.ok || data.ok === false) throw new Error(data.error || `HTTP ${response.status}`);
  return data;
}

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>"']/g, (ch) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[ch]);
}

function healthBadge(health) {
  if (!health) return '<span class="badge">не проверен</span>';
  if (health.healthy) return `<span class="badge ok">доступен${health.latencyMs != null ? ` · ${health.latencyMs} мс` : ""}</span>`;
  return `<span class="badge bad" title="${escapeHtml(health.error || "")}">недоступен</span>`;
}

function renderStatus(status) {
  state.status = status;
  $("pc-dot").className = `dot${status.pc.proxyEnabled ? " on" : ""}`;
  $("pc-text").textContent = `Прокси на ПК: ${status.pc.proxyEnabled ? "вкл" : "выкл"}`;
  $("pc-toggle").textContent = status.pc.proxyEnabled ? "Выключить на ПК" : "Включить на ПК";
  $("subtitle").textContent = status.upstreams.active
    ? `активный прокси: ${status.upstreams.active.name} (${status.upstreams.active.endpoint})`
    : "нет доступных прокси";
  $("footer-state").textContent = `порт прокси ${status.pc.port} · адресов в списке: ${status.blockedCount} · обновлено ${new Date().toLocaleTimeString("ru-RU")}`;
}

function renderProxies() {
  const tbody = $("proxies-table").querySelector("tbody");
  const proxies = state.proxies;
  tbody.innerHTML = proxies.length
    ? proxies
        .map(
          (item, index) => `
      <tr class="${item.active ? "active-row" : ""}">
        <td>${index + 1}</td>
        <td>${escapeHtml(item.name)}${item.active ? ' <span class="badge ok">активен</span>' : ""}</td>
        <td>${item.type === "ssh" ? "SSH" : "SOCKS5"}</td>
        <td class="muted">${escapeHtml(item.endpoint)}</td>
        <td>${healthBadge(item.health)}</td>
        <td><input type="checkbox" data-action="enabled" data-id="${item.id}" ${item.enabled ? "checked" : ""} /></td>
        <td class="actions">
          <button class="ghost" data-action="up" data-id="${item.id}" ${index === 0 ? "disabled" : ""}>↑</button>
          <button class="ghost" data-action="down" data-id="${item.id}" ${index === proxies.length - 1 ? "disabled" : ""}>↓</button>
          <button class="ghost" data-action="edit" data-id="${item.id}">Изменить</button>
          <button class="danger" data-action="delete" data-id="${item.id}">Удалить</button>
        </td>
      </tr>`,
        )
        .join("")
    : '<tr><td colspan="7" class="muted">Прокси не добавлены</td></tr>';
}

function renderBlocked() {
  $("blocked-table").querySelector("tbody").innerHTML = state.blocked.length
    ? state.blocked
        .map(
          (host) => `<tr><td>${escapeHtml(host)}</td><td class="actions"><button class="danger" data-host="${escapeHtml(host)}">Удалить</button></td></tr>`,
        )
        .join("")
    : '<tr><td colspan="2" class="muted">Список пуст</td></tr>';
  const scanner = state.status?.scanner;
  if (scanner) {
    $("scanner-enabled").checked = Boolean(scanner.enabled);
    $("scanner-interval").value = scanner.intervalMin ?? 15;
    $("auto-push").checked = Boolean(state.status.autoPushToServers);
    $("scan-result").textContent = scanner.lastScan
      ? `Последний скан: ${new Date(scanner.lastScan.at).toLocaleTimeString("ru-RU")}, проверено ${scanner.lastScan.checked}, найдено ${scanner.lastScan.found.length}`
      : "";
  }
  $("push-server").innerHTML = state.servers.map((item) => `<option value="${item.alias}">${escapeHtml(item.label || item.alias)}</option>`).join("");
}

function renderServers() {
  $("servers-table").querySelector("tbody").innerHTML = state.servers.length
    ? state.servers
        .map(
          (item) => `
      <tr>
        <td>${escapeHtml(item.label || item.alias)}<div class="muted">${escapeHtml(item.alias)}</div></td>
        <td>${
          item.running
            ? '<span class="badge ok">работает</span>'
            : item.installed
              ? '<span class="badge warn">установлен, выключен</span>'
              : `<span class="badge bad">${item.error ? escapeHtml(item.error.slice(0, 60)) : "не установлен"}</span>`
        }</td>
        <td>${item.chainRules ?? "—"}</td>
        <td class="actions">
          <button data-srv="${escapeHtml(item.alias)}" data-cmd="install">Установить</button>
          <button data-srv="${escapeHtml(item.alias)}" data-cmd="start">Включить</button>
          <button data-srv="${escapeHtml(item.alias)}" data-cmd="stop">Выключить</button>
          <button class="primary" data-srv="${escapeHtml(item.alias)}" data-cmd="push">Передать список</button>
          <button data-srv="${escapeHtml(item.alias)}" data-cmd="push-proxy">Передать прокси</button>
          <button class="danger" data-srv="${escapeHtml(item.alias)}" data-cmd="remove">Убрать</button>
        </td>
      </tr>`,
        )
        .join("")
    : '<tr><td colspan="4" class="muted">Серверы не добавлены</td></tr>';
}

function fillProxyForm(item) {
  state.editingId = item.id;
  $("new-type").value = item.type;
  $("new-name").value = item.name || "";
  $("new-host").value = item.host || "";
  $("new-port").value = item.port || item.localPort || "";
  $("new-login").value = item.login || "";
  $("new-password").value = item.password || "";
  $("new-ssh").value = item.sshAlias || "";
  $("proxy-add").textContent = "Обновить";
  $("proxy-cancel").hidden = false;
  $("new-type").dispatchEvent(new Event("change"));
}

function clearProxyForm() {
  state.editingId = null;
  for (const id of ["new-name", "new-host", "new-port", "new-login", "new-password", "new-ssh"]) $(id).value = "";
  $("proxy-add").textContent = "Добавить";
  $("proxy-cancel").hidden = true;
  $("new-type").dispatchEvent(new Event("change"));
}

function renderMonitor(data) {
  const latest = data.latest;
  const ip = latest?.mainIp;
  $("mon-ip").innerHTML = ip
    ? `<span class="ip">${escapeHtml(ip.ip || "нет IP")}</span>
       <span class="meta">${escapeHtml([ip.city, ip.country, ip.org].filter(Boolean).join(" · "))}</span>
       <span class="meta">отклик: ${ip.latencyMs != null ? `${ip.latencyMs} мс` : "—"}</span>
       <span class="meta">замер: ${latest ? new Date(latest.at).toLocaleTimeString("ru-RU") : "—"}</span>`
    : '<span class="meta">данных пока нет — нажмите «Проверить сейчас»</span>';

  const proxies = latest ? Object.values(latest.proxies || {}) : [];
  $("mon-proxies").innerHTML = proxies.length
    ? proxies
        .map(
          (item) => `
      <div class="mon-card ${item.id === latest.activeProxyId ? "active" : ""}">
        <h3><span>${escapeHtml(item.name)}</span><span class="badge ${item.ok ? "ok" : "bad"}">${item.ok ? "доступен" : "сбой"}</span></h3>
        <div class="mon-metrics">
          <div class="metric">Отклик<b>${item.latencyMs != null ? `${item.latencyMs} мс` : "—"}</b></div>
          <div class="metric">Скорость<b>${item.speedMbps != null ? `${item.speedMbps} Мбит/с` : "—"}</b></div>
          <div class="metric">Стабильность<b>${item.stability != null ? `${item.stability}%` : "—"}</b></div>
          <div class="metric">Загрузка<b>${item.load != null ? `${item.load} соед.` : "—"}</b></div>
        </div>
        ${item.error ? `<div class="error">${escapeHtml(item.error)}</div>` : ""}
      </div>`,
        )
        .join("")
    : '<div class="muted">Прокси не добавлены</div>';

  $("mon-history").querySelector("tbody").innerHTML = (data.history || [])
    .slice()
    .reverse()
    .slice(0, 20)
    .map(
      (row) => `<tr><td>${new Date(row.at).toLocaleTimeString("ru-RU")}</td><td>${escapeHtml(row.mainIp || "—")}</td><td>${row.latencyMs != null ? `${row.latencyMs} мс` : "—"}</td><td>${escapeHtml((latest?.proxies?.[row.activeProxyId]?.name) || row.activeProxyId || "—")}</td><td>${row.connections ?? "—"}</td></tr>`,
    )
    .join("");

  $("mon-enabled").checked = Boolean(data.enabled);
  $("mon-interval").value = data.intervalSec ?? 60;
}

async function refreshMonitor() {
  try {
    const data = await api("/api/monitor");
    renderMonitor(data);
  } catch (error) {
    toast(`Мониторинг: ${error.message}`, true);
  }
}

async function refreshStatus() {
  try {
    const status = await api("/api/status");
    state.proxies = status.upstreams.proxies;
    state.blocked = status.blocked;
    renderStatus(status);
    renderProxies();
    renderBlocked();
  } catch (error) {
    toast(`Не удалось получить статус: ${error.message}`, true);
  }
}

async function refreshServers() {
  try {
    const data = await api("/api/servers");
    state.servers = data.servers;
    renderServers();
    renderBlocked();
  } catch (error) {
    toast(`Серверы: ${error.message}`, true);
  }
}

async function saveProxies() {
  try {
    const data = await api("/api/proxies", { proxies: state.proxies });
    state.proxies = data.proxies;
    renderProxies();
    toast("Настройки прокси сохранены");
    refreshStatus();
  } catch (error) {
    toast(`Сохранение: ${error.message}`, true);
  }
}

function currentProxiesPayload() {
  return state.proxies.map((item) => ({
    id: item.id,
    name: item.name,
    type: item.type,
    host: item.host,
    port: item.port,
    login: item.login,
    password: item.password,
    sshAlias: item.sshAlias,
    localPort: item.localPort,
    enabled: item.enabled,
  }));
}

function bind() {
  document.querySelectorAll(".tab").forEach((button) => {
    button.addEventListener("click", () => {
      document.querySelectorAll(".tab").forEach((item) => item.classList.remove("active"));
      document.querySelectorAll(".tab-page").forEach((item) => item.classList.remove("active"));
      button.classList.add("active");
      $(`tab-${button.dataset.tab}`).classList.add("active");
    });
  });

  $("pc-toggle").addEventListener("click", async () => {
    const enable = !(state.status?.pc?.proxyEnabled);
    $("pc-toggle").disabled = true;
    try {
      const data = await api("/api/pc/toggle", { enabled: enable });
      toast(data.pcProxyEnabled ? "Прокси на ПК включён" : "Прокси на ПК выключен");
      await refreshStatus();
    } catch (error) {
      toast(`ПК: ${error.message}`, true);
    } finally {
      $("pc-toggle").disabled = false;
    }
  });

  $("proxies-check").addEventListener("click", async () => {
    $("proxies-check").disabled = true;
    try {
      const data = await api("/api/proxies/check", {});
      state.proxies = data.proxies;
      renderProxies();
      toast(`Проверено прокси: ${data.proxies.length}, активен: ${data.active ? data.active.name : "нет"}`);
    } catch (error) {
      toast(`Проверка: ${error.message}`, true);
    } finally {
      $("proxies-check").disabled = false;
    }
  });

  $("proxies-save").addEventListener("click", saveProxies);

  $("proxies-table").addEventListener("click", (event) => {
    const button = event.target.closest("button");
    if (!button) return;
    const id = button.dataset.id;
    const index = state.proxies.findIndex((item) => item.id === id);
    if (index < 0) return;
    if (button.dataset.action === "up" && index > 0) {
      [state.proxies[index - 1], state.proxies[index]] = [state.proxies[index], state.proxies[index - 1]];
    }
    if (button.dataset.action === "down" && index < state.proxies.length - 1) {
      [state.proxies[index + 1], state.proxies[index]] = [state.proxies[index], state.proxies[index + 1]];
    }
    if (button.dataset.action === "delete") {
      state.proxies.splice(index, 1);
      if (state.editingId === id) clearProxyForm();
    }
    if (button.dataset.action === "edit") {
      fillProxyForm(state.proxies[index]);
      return;
    }
    renderProxies();
    saveProxies();
  });

  $("proxies-table").addEventListener("change", (event) => {
    const input = event.target.closest('input[type="checkbox"][data-action="enabled"]');
    if (!input) return;
    const item = state.proxies.find((entry) => entry.id === input.dataset.id);
    if (item) item.enabled = input.checked;
    saveProxies();
  });

  $("proxy-add").addEventListener("click", () => {
    const type = $("new-type").value;
    const name = $("new-name").value.trim() || `Прокси ${state.proxies.length + 1}`;
    if (type === "ssh") {
      const alias = $("new-ssh").value.trim();
      if (!alias) return toast("Укажите SSH-алиас", true);
      const payload = { name, type, sshAlias: alias, localPort: Number($("new-port").value || 1080 + state.proxies.length + 1), enabled: true };
      if (state.editingId) {
        const item = state.proxies.find((entry) => entry.id === state.editingId);
        Object.assign(item, payload, { host: undefined, port: undefined, login: undefined, password: undefined });
      } else {
        if (state.proxies.length >= 5) return toast("Максимум 5 прокси", true);
        state.proxies.push({ id: `proxy-${Date.now()}`, ...payload });
      }
    } else {
      const host = $("new-host").value.trim();
      const port = Number($("new-port").value || 1080);
      if (!host || !port) return toast("Укажите хост и порт SOCKS5", true);
      const payload = {
        name,
        type: "socks5",
        host,
        port,
        login: $("new-login").value,
        password: $("new-password").value,
        enabled: true,
      };
      if (state.editingId) {
        const item = state.proxies.find((entry) => entry.id === state.editingId);
        Object.assign(item, payload, { sshAlias: undefined, localPort: undefined });
      } else {
        if (state.proxies.length >= 5) return toast("Максимум 5 прокси", true);
        state.proxies.push({ id: `proxy-${Date.now()}`, ...payload });
      }
    }
    clearProxyForm();
    renderProxies();
    saveProxies();
  });

  $("proxy-cancel").addEventListener("click", clearProxyForm);

  $("new-type").addEventListener("change", () => {
    const ssh = $("new-type").value === "ssh";
    $("new-host").disabled = ssh;
    $("new-login").disabled = ssh;
    $("new-password").disabled = ssh;
    $("new-ssh").disabled = !ssh;
  });

  $("host-add").addEventListener("click", async () => {
    const host = $("new-host").value.trim();
    if (!host) return;
    try {
      const data = await api("/api/blocked/add", { host });
      state.blocked = data.blocked;
      $("new-host").value = "";
      renderBlocked();
      toast(`Добавлен ${host}`);
    } catch (error) {
      toast(error.message, true);
    }
  });

  $("blocked-table").addEventListener("click", async (event) => {
    const button = event.target.closest("button[data-host]");
    if (!button) return;
    try {
      const data = await api("/api/blocked/remove", { host: button.dataset.host });
      state.blocked = data.blocked;
      renderBlocked();
    } catch (error) {
      toast(error.message, true);
    }
  });

  $("scan-now").addEventListener("click", async () => {
    $("scan-now").disabled = true;
    try {
      const result = await api("/api/scan", {});
      if (result.ok === false) throw new Error(result.error);
      toast(`Скан завершён: проверено ${result.checked}, добавлено ${result.found.length}`);
      await refreshStatus();
    } catch (error) {
      toast(`Скан: ${error.message}`, true);
    } finally {
      $("scan-now").disabled = false;
    }
  });

  $("scanner-enabled").addEventListener("change", async (event) => {
    try {
      await api("/api/scanner", { enabled: event.target.checked, intervalMin: Number($("scanner-interval").value || 15) });
      refreshStatus();
    } catch (error) {
      toast(error.message, true);
    }
  });

  $("scanner-interval").addEventListener("change", async (event) => {
    try {
      await api("/api/scanner", { enabled: $("scanner-enabled").checked, intervalMin: Number(event.target.value || 15) });
      refreshStatus();
    } catch (error) {
      toast(error.message, true);
    }
  });

  $("auto-push").addEventListener("change", async (event) => {
    try {
      await api("/api/settings", { autoPushToServers: event.target.checked });
      refreshStatus();
    } catch (error) {
      toast(error.message, true);
    }
  });

  $("push-list").addEventListener("click", async () => {
    const alias = $("push-server").value;
    if (!alias) return toast("Сначала добавьте сервер", true);
    $("push-list").disabled = true;
    try {
      const result = await api("/api/servers/push", { alias });
      toast(`Передано ${result.pushed} из ${result.total} адресов на ${alias}`);
    } catch (error) {
      toast(`Передача: ${error.message}`, true);
    } finally {
      $("push-list").disabled = false;
    }
  });

  $("server-add").addEventListener("click", async () => {
    const alias = $("new-alias").value.trim();
    if (!alias) return toast("Укажите SSH-алиас", true);
    $("server-add").disabled = true;
    try {
      await api("/api/servers/add", { alias, label: $("new-label").value.trim() });
      $("new-alias").value = "";
      $("new-label").value = "";
      await refreshServers();
      toast(`Сервер ${alias} добавлен`);
    } catch (error) {
      toast(`Сервер: ${error.message}`, true);
    } finally {
      $("server-add").disabled = false;
    }
  });

  $("servers-table").addEventListener("click", async (event) => {
    const button = event.target.closest("button[data-srv]");
    if (!button) return;
    const alias = button.dataset.srv;
    const cmd = button.dataset.cmd;
    button.disabled = true;
    try {
      if (cmd === "install") await api("/api/servers/install", { alias });
      else if (cmd === "push") await api("/api/servers/push", { alias });
      else if (cmd === "push-proxy") await api("/api/servers/push-proxy", { alias });
      else if (cmd === "remove") await api("/api/servers/remove", { alias });
      else await api("/api/servers/control", { alias, action: cmd });
      toast(`Сервер ${alias}: ${cmd === "install" ? "установлен" : cmd === "push" ? "список передан" : cmd === "push-proxy" ? "прокси передан" : cmd === "remove" ? "убран" : cmd === "start" ? "включён" : "выключен"}`);
      await refreshServers();
    } catch (error) {
      toast(`Сервер ${alias}: ${error.message}`, true);
    } finally {
      button.disabled = false;
    }
  });

  $("logs-refresh").addEventListener("click", async () => {
    try {
      const data = await api("/api/logs");
      $("logs").textContent = data.logs.join("\n");
    } catch (error) {
      toast(error.message, true);
    }
  });

  $("mon-sample").addEventListener("click", async () => {
    $("mon-sample").disabled = true;
    try {
      await api("/api/monitor/sample", {});
      await refreshMonitor();
      toast("Замер выполнен");
    } catch (error) {
      toast(`Мониторинг: ${error.message}`, true);
    } finally {
      $("mon-sample").disabled = false;
    }
  });

  $("mon-enabled").addEventListener("change", async (event) => {
    try {
      await api("/api/monitor/config", { enabled: event.target.checked, intervalSec: Number($("mon-interval").value || 60) });
      await refreshMonitor();
    } catch (error) {
      toast(error.message, true);
    }
  });

  $("mon-interval").addEventListener("change", async (event) => {
    try {
      await api("/api/monitor/config", { enabled: $("mon-enabled").checked, intervalSec: Number(event.target.value || 60) });
      await refreshMonitor();
    } catch (error) {
      toast(error.message, true);
    }
  });

  $("new-type").dispatchEvent(new Event("change"));
}

async function boot() {
  bind();
  const initialTab = String(location.hash || "").replace("#", "");
  if (initialTab) document.querySelector(`.tab[data-tab="${initialTab}"]`)?.click();
  await refreshStatus();
  await refreshServers();
  await refreshMonitor();
  try {
    const data = await api("/api/logs");
    $("logs").textContent = data.logs.join("\n");
  } catch {
    /* logs are optional */
  }
  setInterval(refreshStatus, 5000);
  setInterval(refreshServers, 30000);
  setInterval(refreshMonitor, 15000);
}

boot();
