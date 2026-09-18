"use strict";

const $ = (sel, root = document) => root.querySelector(sel);

const state = {
  me: null,
  tenants: [],
  activeTenant: null,
  posts: [],
  post: null,
  draft: null,
  publicPost: null,
  dirty: false,
  busy: false,
};

function esc(value) {
  return String(value ?? "").replace(/[&<>"']/g, (c) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;",
  }[c]));
}

function toast(message, kind = "success") {
  const host = document.getElementById("toast");
  const el = document.createElement("div");
  el.className = `alert alert-${kind} shadow`;
  el.textContent = message;
  host.appendChild(el);
  setTimeout(() => el.remove(), 4000);
}

async function api(method, path, body) {
  const res = await fetch(path, {
    method,
    headers: body !== undefined ? { "Content-Type": "application/json" } : {},
    credentials: "same-origin",
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  let data = null;
  if (res.status !== 204) {
    const text = await res.text();
    if (text) {
      try {
        data = JSON.parse(text);
      } catch {
        data = null;
      }
    }
  }
  if (!res.ok) {
    const message = (data && data.error && data.error.message) || `HTTP ${res.status}`;
    const err = new Error(message);
    err.status = res.status;
    err.code = data && data.error && data.error.code;
    throw err;
  }
  return data;
}

function fmtDate(value) {
  if (!value) return "";
  const d = new Date(value);
  return Number.isNaN(d.getTime()) ? "" : d.toLocaleString();
}

function fromPost(p) {
  return {
    title: p.title || "",
    slug: p.slug || "",
    excerpt: p.excerpt || "",
    content_markdown: p.content_markdown || "",
  };
}

function newDraft() {
  return { title: "", slug: "", excerpt: "", content_markdown: "" };
}

function parseHash() {
  const raw = location.hash.replace(/^#\/?/, "");
  const parts = raw.split("/");
  if (parts[0] === "login") return { name: "login" };
  if (parts[0] === "view") return { name: "view", slug: decodeURIComponent(parts.slice(1).join("/")) };
  if (parts[0] === "posts" && parts[1] === "new") return { name: "new" };
  if (parts[0] === "posts" && parts[1]) return { name: "editor", id: parts[1] };
  return { name: "posts" };
}

/* ------------------------------- data ------------------------------- */

async function login(email, password) {
  await api("POST", "/auth/login", { email, password });
  await refreshMe();
  await loadTenants();
  if (!state.me.tenant_id && state.tenants.length) {
    await api("PUT", "/auth/me/active-tenant", { tenant_id: state.tenants[0].id });
    await refreshMe();
    await loadTenants();
  }
  await loadPosts();
  location.hash = "#/posts";
  toast("Signed in");
}

async function logout() {
  try {
    await api("POST", "/auth/logout");
  } catch {
    /* clear local state regardless */
  }
  Object.assign(state, {
    me: null, tenants: [], activeTenant: null, posts: [],
    post: null, draft: null, publicPost: null, dirty: false,
  });
  location.hash = "#/login";
  router();
}

async function refreshMe() {
  state.me = await api("GET", "/auth/me");
}

async function loadTenants() {
  const memberships = (state.me && state.me.memberships) || [];
  const byId = new Map(memberships.map((m) => [m.tenant_id, m]));
  if (state.me && state.me.platform) {
    const out = await api("GET", "/admin/tenants");
    state.tenants = (out.tenants || []).map((t) => {
      const m = byId.get(t.id);
      return { id: t.id, slug: t.slug, name: t.name, role: m ? m.role : "owner" };
    });
  } else {
    state.tenants = memberships.map((m) => ({ id: m.tenant_id, slug: m.slug, name: m.name, role: m.role }));
  }
  const activeId = state.me ? state.me.tenant_id : null;
  state.activeTenant = state.tenants.find((t) => t.id === activeId) || null;
}

async function loadPosts() {
  if (!state.me || !state.me.tenant_id) {
    state.posts = [];
    return;
  }
  const out = await api("GET", "/admin/posts");
  state.posts = out.posts || [];
}

async function switchTenant(id) {
  try {
    await api("PUT", "/auth/me/active-tenant", { tenant_id: id });
    await refreshMe();
    await loadTenants();
    await loadPosts();
    state.post = null;
    state.draft = null;
    location.hash = "#/posts";
    router();
    toast("Switched tenant");
  } catch (err) {
    toast(err.message, "error");
  }
}

async function saveEditor() {
  const d = state.draft;
  if (!d || !d.title.trim()) {
    toast("Title is required", "error");
    return false;
  }
  if (state.busy) return false;
  state.busy = true;
  const isNew = !state.post;
  const body = { title: d.title, excerpt: d.excerpt, content_markdown: d.content_markdown };
  if (isNew) {
    if (d.slug.trim()) body.slug = d.slug.trim();
  } else if (state.post.status !== "published" && d.slug.trim() && d.slug.trim() !== state.post.slug) {
    body.slug = d.slug.trim();
  }
  try {
    const saved = isNew
      ? await api("POST", "/admin/posts", body)
      : await api("PATCH", `/admin/posts/${state.post.id}`, body);
    state.post = saved;
    state.draft = fromPost(saved);
    state.dirty = false;
    await loadPosts();
    if (isNew) {
      location.hash = `#/posts/${saved.id}`;
    } else {
      renderEditor();
    }
    toast("Saved");
    return true;
  } catch (err) {
    toast(err.message, "error");
    return false;
  } finally {
    state.busy = false;
  }
}

async function publishPost() {
  if (!state.post) return;
  if (state.dirty && !(await saveEditor())) return;
  try {
    state.post = await api("POST", `/admin/posts/${state.post.id}/publish`);
    state.draft = fromPost(state.post);
    state.dirty = false;
    await loadPosts();
    renderEditor();
    toast("Published");
  } catch (err) {
    toast(err.message, "error");
  }
}

async function unpublishPost() {
  if (!state.post) return;
  try {
    state.post = await api("POST", `/admin/posts/${state.post.id}/unpublish`);
    state.draft = fromPost(state.post);
    state.dirty = false;
    await loadPosts();
    renderEditor();
    toast("Unpublished");
  } catch (err) {
    toast(err.message, "error");
  }
}

async function deletePost() {
  if (!state.post) return;
  if (!window.confirm("Delete this post?")) return;
  try {
    await api("DELETE", `/admin/posts/${state.post.id}`);
    state.post = null;
    state.draft = null;
    await loadPosts();
    location.hash = "#/posts";
    toast("Deleted");
  } catch (err) {
    toast(err.message, "error");
  }
}

/* ------------------------------ views ------------------------------- */

function navbar() {
  const active = state.activeTenant;
  const options = state.tenants
    .map((t) => `<option value="${t.id}" ${active && active.id === t.id ? "selected" : ""}>${esc(t.name)} · ${esc(t.slug)}</option>`)
    .join("");
  const role = (state.me && state.me.role) || (active && active.role) || "";
  const roleClass = role === "author" ? "badge-info" : role === "editor" ? "badge-primary" : "badge-success";

  return `
  <div class="navbar bg-base-200 border-b border-base-content/10 px-4 sticky top-0 z-40">
    <div class="navbar-start gap-2 min-w-0">
      <a href="#/posts" class="font-bold shrink-0">Open Blog</a>
      ${state.tenants.length
        ? `<select id="tenant-select" class="select select-sm select-bordered max-w-44">${options}</select>`
        : `<span class="badge badge-ghost badge-sm">no tenant</span>`}
      ${role ? `<span class="badge badge-sm badge-soft ${roleClass} hidden sm:inline-flex">${esc(role)}</span>` : ""}
    </div>
    <div class="navbar-end gap-1">
      ${state.me && state.me.platform ? `<button class="btn btn-sm btn-ghost" data-new-tenant>New tenant</button>` : ""}
      <button class="btn btn-sm btn-primary" data-new-post>New post</button>
      <button class="btn btn-sm btn-ghost" data-logout>Sign out</button>
    </div>
  </div>`;
}

function renderLoading() {
  $("#app").innerHTML = navbar() +
    `<main class="mx-auto max-w-6xl p-4"><span class="loading loading-spinner loading-lg"></span></main>`;
  bindCommon();
}

function renderLogin() {
  const app = $("#app");
  app.innerHTML = `
  <div class="min-h-screen flex items-center justify-center p-4">
    <div class="card card-border bg-base-200 w-full max-w-sm">
      <div class="card-body">
        <h1 class="card-title">Open Blog</h1>
        <p class="text-sm text-base-content/60">Sign in to manage posts.</p>
        <form id="login-form" class="mt-2">
          <fieldset class="fieldset">
            <legend class="fieldset-legend">Email</legend>
            <input name="email" type="email" class="input w-full" autocomplete="username" required>
          </fieldset>
          <fieldset class="fieldset">
            <legend class="fieldset-legend">Password</legend>
            <input name="password" type="password" class="input w-full" autocomplete="current-password" required>
          </fieldset>
          <button class="btn btn-primary w-full mt-3" type="submit">Sign in</button>
        </form>
      </div>
    </div>
  </div>`;
  $("#login-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const fd = new FormData(event.currentTarget);
    try {
      await login(fd.get("email"), fd.get("password"));
    } catch (err) {
      toast(err.message, "error");
    }
  });
}

function statusBadge(status) {
  const cls = status === "published" ? "badge-success" : status === "archived" ? "badge-ghost" : "badge-warning";
  return `<span class="badge badge-sm badge-soft ${cls}">${esc(status)}</span>`;
}

function renderPosts() {
  const active = state.activeTenant;
  const rows = state.posts.length
    ? state.posts.map((p) => `
      <tr>
        <td class="font-medium"><a class="link link-hover" href="#/posts/${p.id}">${esc(p.title)}</a></td>
        <td>${statusBadge(p.status)}</td>
        <td class="text-base-content/50 hidden sm:table-cell">${esc(fmtDate(p.created_at))}</td>
        <td class="text-right whitespace-nowrap">
          <a class="btn btn-xs btn-ghost" href="#/posts/${p.id}">Edit</a>
          ${p.status === "published" ? `<a class="btn btn-xs btn-ghost" href="#/view/${encodeURIComponent(p.slug)}">View</a>` : ""}
        </td>
      </tr>`).join("")
    : `<tr><td colspan="4" class="text-center text-base-content/50 py-8">No posts yet. Create one with “New post”.</td></tr>`;

  $("#app").innerHTML = navbar() + `
  <main class="mx-auto max-w-6xl p-4">
    <div class="flex items-center justify-between mb-3">
      <h1 class="text-xl font-bold">Posts${active ? ` <span class="text-base-content/40 font-normal">/ ${esc(active.name)}</span>` : ""}</h1>
    </div>
    ${active ? "" : `<div role="alert" class="alert alert-warning mb-3"><span>No active tenant. Select one from the switcher or create a tenant.</span></div>`}
    <div class="overflow-x-auto rounded-box border border-base-content/10 bg-base-200">
      <table class="table table-sm">
        <thead><tr><th>Title</th><th>Status</th><th class="hidden sm:table-cell">Created</th><th></th></tr></thead>
        <tbody>${rows}</tbody>
      </table>
    </div>
  </main>`;
  bindCommon();
}

function editorShell(inner) {
  return navbar() + `<main class="mx-auto max-w-6xl p-4">${inner}</main>`;
}

function renderEditor() {
  const isNew = !state.post;
  const p = state.post || { status: "draft", slug: "", content_html: "" };
  const d = state.draft || newDraft();

  $("#app").innerHTML = editorShell(`
    <div class="flex flex-wrap items-center gap-2 mb-3">
      <a href="#/posts" class="btn btn-xs btn-ghost">← Posts</a>
      ${isNew ? `<span class="badge badge-sm badge-soft badge-warning">new draft</span>` : statusBadge(p.status)}
      <span id="dirty-badge" class="badge badge-sm badge-warning badge-soft ${state.dirty ? "" : "invisible"}">unsaved</span>
    </div>
    <div class="grid sm:grid-cols-3 gap-2 mb-2">
      <input id="f-title" class="input input-bordered sm:col-span-2" placeholder="Title" value="${esc(d.title)}">
      <input id="f-slug" class="input input-bordered font-mono" placeholder="slug" value="${esc(d.slug)}"
             ${p.status === "published" ? "disabled" : ""}>
    </div>
    <input id="f-excerpt" class="input input-bordered w-full mb-3" placeholder="Excerpt" value="${esc(d.excerpt)}">
    <div class="grid md:grid-cols-2 gap-3">
      <div class="min-w-0">
        <div class="label py-1"><span class="label-text text-xs">content_markdown</span></div>
        <textarea id="f-body" class="textarea textarea-bordered w-full h-[28rem] font-mono text-sm">${esc(d.content_markdown)}</textarea>
      </div>
      <div class="min-w-0">
        <div class="label py-1"><span class="label-text text-xs">preview · server content_html</span></div>
        <div class="preview border border-base-content/10 rounded-box p-4 h-[28rem] overflow-auto bg-base-200">
          ${p.content_html ? p.content_html : `<p class="text-base-content/40">Save to render the preview.</p>`}
        </div>
      </div>
    </div>
    <div class="flex flex-wrap gap-2 mt-3">
      <button class="btn btn-sm btn-primary" data-save>Save</button>
      ${isNew ? "" : `<a class="btn btn-sm btn-ghost" href="/admin/posts/${p.id}/html" target="_blank" rel="noopener">Preview HTML</a>`}
      ${isNew
        ? ""
        : p.status === "published"
          ? `<button class="btn btn-sm" data-unpublish>Unpublish</button>
             <a class="btn btn-sm btn-ghost" href="#/view/${encodeURIComponent(p.slug)}">View public</a>`
          : `<button class="btn btn-sm btn-success" data-publish>Publish</button>`}
      ${isNew ? "" : `<button class="btn btn-sm btn-ghost text-error ml-auto" data-delete>Delete</button>`}
    </div>`);
  bindEditor();
  bindCommon();
}

function bindEditor() {
  const inputs = ["#f-title", "#f-slug", "#f-excerpt", "#f-body"];
  const onInput = () => {
    state.draft = {
      title: $("#f-title").value,
      slug: $("#f-slug").value,
      excerpt: $("#f-excerpt").value,
      content_markdown: $("#f-body").value,
    };
    state.dirty = true;
    const badge = $("#dirty-badge");
    if (badge) badge.classList.remove("invisible");
  };
  inputs.forEach((sel) => {
    const el = $(sel);
    if (el) el.addEventListener("input", onInput);
  });
  const save = $("[data-save]");
  if (save) save.addEventListener("click", saveEditor);
  const publish = $("[data-publish]");
  if (publish) publish.addEventListener("click", publishPost);
  const unpublish = $("[data-unpublish]");
  if (unpublish) unpublish.addEventListener("click", unpublishPost);
  const del = $("[data-delete]");
  if (del) del.addEventListener("click", deletePost);
}

async function loadPublic(slug) {
  if (!state.activeTenant) throw new Error("no active tenant");
  const tenant = encodeURIComponent(state.activeTenant.slug);
  return api("GET", `/public/${tenant}/posts/${encodeURIComponent(slug)}`);
}

function renderPublic() {
  const pp = state.publicPost;
  let body;
  if (!pp || pp.error) {
    body = `<div role="alert" class="alert alert-warning"><span>Not available. The post may be a draft or was unpublished.</span></div>`;
  } else {
    body = `
    <article class="preview max-w-3xl mx-auto">
      <h1>${esc(pp.title)}</h1>
      <p class="text-sm text-base-content/50">${esc(pp.author || "")}${pp.published_at ? ` · ${esc(fmtDate(pp.published_at))}` : ""}</p>
      ${pp.excerpt ? `<p class="italic text-base-content/70">${esc(pp.excerpt)}</p>` : ""}
      ${pp.content_html || ""}
    </article>`;
  }
  $("#app").innerHTML = navbar() + `<main class="p-4">${body}</main>`;
  bindCommon();
}

function bindCommon() {
  document.querySelectorAll("[data-logout]").forEach((el) => el.addEventListener("click", logout));
  document.querySelectorAll("[data-new-post]").forEach((el) => el.addEventListener("click", () => {
    location.hash = "#/posts/new";
  }));
  document.querySelectorAll("[data-new-tenant]").forEach((el) => el.addEventListener("click", () => {
    document.getElementById("tenant-dialog").showModal();
  }));
  const sel = $("#tenant-select");
  if (sel) sel.addEventListener("change", () => switchTenant(sel.value));
}

/* ------------------------------ router ------------------------------ */

async function router() {
  if (!state.me) {
    renderLogin();
    return;
  }
  const route = parseHash();
  try {
    if (route.name === "editor") {
      renderLoading();
      const p = await api("GET", `/admin/posts/${route.id}`);
      state.post = p;
      state.draft = fromPost(p);
      state.dirty = false;
      renderEditor();
    } else if (route.name === "new") {
      state.post = null;
      state.draft = newDraft();
      state.dirty = false;
      renderEditor();
    } else if (route.name === "view") {
      renderLoading();
      try {
        state.publicPost = await loadPublic(route.slug);
      } catch (err) {
        state.publicPost = { error: err };
      }
      renderPublic();
    } else {
      renderPosts();
    }
  } catch (err) {
    if (err.status === 401) {
      state.me = null;
      renderLogin();
      return;
    }
    toast(err.message, "error");
    renderPosts();
  }
}

/* ------------------------------- init ------------------------------- */

async function init() {
  document.getElementById("tenant-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const fd = new FormData(event.currentTarget);
    try {
      const tenant = await api("POST", "/admin/tenants", { slug: fd.get("slug"), name: fd.get("name") });
      document.getElementById("tenant-dialog").close();
      event.currentTarget.reset();
      await loadTenants();
      await switchTenant(tenant.id);
      toast("Tenant created");
    } catch (err) {
      toast(err.message, "error");
    }
  });
  document.querySelectorAll("[data-close-dialog]").forEach((el) => el.addEventListener("click", () => {
    document.getElementById("tenant-dialog").close();
  }));

  try {
    await refreshMe();
  } catch {
    state.me = null;
  }

  if (state.me) {
    try {
      await loadTenants();
      if (!state.me.tenant_id && state.tenants.length) {
        await api("PUT", "/auth/me/active-tenant", { tenant_id: state.tenants[0].id });
        await refreshMe();
        await loadTenants();
      }
      await loadPosts();
    } catch (err) {
      toast(err.message, "error");
    }
  }

  window.addEventListener("hashchange", router);
  await router();
}

init();
