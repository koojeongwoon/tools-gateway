export const DASHBOARD_HTML = `<!DOCTYPE html>
<html lang="ko">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Tools Gateway - Unified MCP Hub</title>
  <style>
    :root {
      --bg: #0d1117;
      --card-bg: #161b22;
      --border: #30363d;
      --text: #c9d1d9;
      --text-bright: #f0f6fc;
      --accent: #58a6ff;
      --accent-hover: #1f6feb;
      --danger: #f85149;
      --success: #3fb950;
      --tag-bg: #21262d;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
    body { background: var(--bg); color: var(--text); padding: 2rem 1rem; display: flex; justify-content: center; }
    .container { max-width: 900px; width: 100%; display: flex; flex-direction: column; gap: 1.5rem; }
    header { display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid var(--border); padding-bottom: 1.2rem; }
    .title-area h1 { color: var(--text-bright); font-size: 1.5rem; display: flex; align-items: center; gap: 0.5rem; }
    .title-area p { font-size: 0.85rem; color: #8b949e; margin-top: 0.2rem; }
    .user-pill { background: var(--tag-bg); border: 1px solid var(--border); padding: 0.4rem 0.8rem; border-radius: 20px; font-size: 0.85rem; display: flex; align-items: center; gap: 0.6rem; }
    .btn { padding: 0.5rem 1rem; border-radius: 6px; font-size: 0.85rem; cursor: pointer; border: 1px solid transparent; transition: 0.15s; font-weight: 500; }
    .btn-primary { background: var(--accent); color: #0d1117; }
    .btn-primary:hover { background: var(--accent-hover); color: #fff; }
    .btn-outline { background: transparent; border-color: var(--border); color: var(--text); }
    .btn-outline:hover { border-color: #8b949e; color: var(--text-bright); }
    .btn-danger { background: transparent; border-color: var(--border); color: var(--danger); }
    .btn-danger:hover { background: rgba(248, 81, 73, 0.15); border-color: var(--danger); }
    
    .card { background: var(--card-bg); border: 1px solid var(--border); border-radius: 8px; padding: 1.5rem; }
    .card h2 { font-size: 1.15rem; color: var(--text-bright); margin-bottom: 0.8rem; display: flex; justify-content: space-between; align-items: center; }
    
    .key-item { display: flex; justify-content: space-between; align-items: center; padding: 0.9rem; background: var(--bg); border: 1px solid var(--border); border-radius: 6px; margin-bottom: 0.6rem; }
    .key-info h4 { color: var(--text-bright); font-size: 0.95rem; }
    .key-info p { font-size: 0.75rem; color: #8b949e; margin-top: 0.2rem; }
    .key-prefix { font-family: monospace; background: var(--tag-bg); padding: 0.2rem 0.4rem; border-radius: 4px; color: var(--accent); }
    
    .modal { display: none; position: fixed; inset: 0; background: rgba(0,0,0,0.7); justify-content: center; align-items: center; padding: 1rem; }
    .modal-content { background: var(--card-bg); border: 1px solid var(--border); border-radius: 8px; max-width: 480px; width: 100%; padding: 1.5rem; }
    .modal-content h3 { color: var(--text-bright); margin-bottom: 1rem; }
    .input-group { margin-bottom: 1rem; display: flex; flex-direction: column; gap: 0.4rem; }
    .input-group label { font-size: 0.85rem; color: #8b949e; }
    .input-group input { background: var(--bg); border: 1px solid var(--border); color: var(--text-bright); padding: 0.6rem; border-radius: 6px; font-size: 0.9rem; }
    .input-group input:focus { outline: none; border-color: var(--accent); }
    .modal-actions { display: flex; justify-content: flex-end; gap: 0.5rem; margin-top: 1.2rem; }
    
    .secret-box { background: #0b1d3a; border: 1px solid #1f6feb; border-radius: 6px; padding: 1rem; margin-top: 1rem; }
    .secret-box p { font-size: 0.8rem; color: #8b949e; margin-bottom: 0.5rem; }
    .secret-token { font-family: monospace; color: #79c0ff; word-break: break-all; user-select: all; font-size: 0.85rem; }
    
    pre { background: var(--bg); border: 1px solid var(--border); padding: 1rem; border-radius: 6px; font-family: monospace; font-size: 0.8rem; overflow-x: auto; color: #79c0ff; }
    .tag { display: inline-block; padding: 0.2rem 0.5rem; border-radius: 12px; font-size: 0.75rem; background: var(--tag-bg); border: 1px solid var(--border); margin-right: 0.4rem; }
  </style>
</head>
<body>
  <div class="container">
    <header>
      <div class="title-area">
        <h1>🚀 Tools Gateway</h1>
        <p>Unified MCP Hub & Secure Proxy for AI Agents</p>
      </div>
      <div id="auth-area">
        <button class="btn btn-primary" onclick="location.href='/api/v1/auth/login'">통합인증으로 로그인</button>
      </div>
    </header>

    <div id="dashboard-content" style="display: none; display: flex; flex-direction: column; gap: 1.5rem;">
      <!-- API Keys Section -->
      <section class="card">
        <h2>
          🔑 내 API Key 목록
          <button class="btn btn-primary" onclick="openKeyModal()">+ 새 API Key 발급</button>
        </h2>
        <div id="keys-list" style="margin-top: 1rem;">
          <p style="color: #8b949e; font-size: 0.85rem;">발급된 키가 없습니다.</p>
        </div>
      </section>

      <!-- Permissions / Available Tools -->
      <section class="card">
        <h2>📦 사용 가능한 MCP 도구 & 권한</h2>
        <div id="perms-list" style="margin-top: 0.8rem;">
          <p style="color: #8b949e; font-size: 0.85rem;">로딩 중...</p>
        </div>
      </section>

      <!-- Client Config Guide -->
      <section class="card">
        <h2>📋 AI 클라이언트 연동 가이드</h2>
        <p style="font-size: 0.85rem; color: #8b949e; margin-bottom: 0.8rem;">
          Cursor, Claude Desktop 등의 <code>mcpServers</code> 설정에 아래 JSON을 추가하세요:
        </p>
        <pre><code>{
  "mcpServers": {
    "tools-gateway": {
      "url": "https://tools-gateway.lynply.com/mcp",
      "headers": {
        "Authorization": "Bearer &lt;YOUR_API_KEY&gt;"
      }
    }
  }
}</code></pre>
      </section>
    </div>
  </div>

  <!-- Key Creation Modal -->
  <div id="key-modal" class="modal">
    <div class="modal-content">
      <h3>🔑 새 API Key 생성</h3>
      <form id="key-form" onsubmit="createApiKey(event)">
        <div class="input-group">
          <label for="key-name">키 이름 / 용도</label>
          <input type="text" id="key-name" placeholder="예: Cursor Mac Mini용, Slackbot용" required>
        </div>
        <div id="created-secret-area" style="display: none;">
          <div class="secret-box">
            <p>⚠️ <strong>키가 생성되었습니다!</strong> 이 키는 다시 표시되지 않으니 지금 복사해두세요:</p>
            <div id="raw-key-value" class="secret-token"></div>
          </div>
        </div>
        <div class="modal-actions">
          <button type="button" class="btn btn-outline" onclick="closeKeyModal()">닫기</button>
          <button type="submit" id="submit-key-btn" class="btn btn-primary">생성하기</button>
        </div>
      </form>
    </div>
  </div>

  <script>
    let currentUser = null;

    async function init() {
      try {
        const res = await fetch('/api/v1/auth/me');
        if (res.ok) {
          const data = await res.json();
          if (data.authenticated && data.user) {
            currentUser = data.user;
            renderAuthUser(currentUser);
            loadKeys();
            loadPermissions();
            document.getElementById('dashboard-content').style.display = 'flex';
            return;
          }
        }
      } catch (e) {}
      document.getElementById('dashboard-content').style.display = 'none';
    }

    function renderAuthUser(user) {
      const authArea = document.getElementById('auth-area');
      authArea.innerHTML = \`
        <div class="user-pill">
          <span>👤 <strong>\${user.name || user.email}</strong></span>
          <button class="btn btn-outline" style="padding: 0.2rem 0.5rem; font-size: 0.75rem;" onclick="logout()">로그아웃</button>
        </div>
      \`;
    }

    async function logout() {
      await fetch('/api/v1/auth/logout', { method: 'POST' });
      location.reload();
    }

    async function loadKeys() {
      const listDiv = document.getElementById('keys-list');
      try {
        const res = await fetch('/api/v1/keys');
        if (!res.ok) return;
        const keys = await res.json();
        if (keys.length === 0) {
          listDiv.innerHTML = '<p style="color: #8b949e; font-size: 0.85rem;">발급된 키가 없습니다. 새 키를 발급해 보세요.</p>';
          return;
        }
        listDiv.innerHTML = keys.map(k => \`
          <div class="key-item">
            <div class="key-info">
              <h4>\${k.name} <span class="key-prefix">\${k.key_prefix}...</span></h4>
              <p>생성일: \${new Date(k.created_at).toLocaleDateString()} | 스코프: \${k.allowed_scopes.join(', ')}</p>
            </div>
            <button class="btn btn-danger" onclick="revokeKey('\${k.id}')">삭제</button>
          </div>
        \`).join('');
      } catch (e) {
        listDiv.innerHTML = '<p style="color: var(--danger); font-size: 0.85rem;">키 목록 로드 실패</p>';
      }
    }

    async function loadPermissions() {
      const permsDiv = document.getElementById('perms-list');
      try {
        const res = await fetch('/api/v1/permissions');
        if (!res.ok) return;
        const data = await res.json();
        let html = '';
        if (data.tools && data.tools.length > 0) {
          html += '<div style="margin-bottom: 0.8rem;"><strong>허용된 MCP 도구:</strong><br>';
          html += data.tools.map(t => \`<span class="tag">⚡ \${t}</span>\`).join('');
          html += '</div>';
        }
        if (data.services && data.services.length > 0) {
          html += '<div><strong>서비스 권한:</strong><br>';
          html += data.services.map(s => \`<span class="tag">\${s.service_name} (\${s.allowed_actions.join(', ')})</span>\`).join('');
          html += '</div>';
        }
        permsDiv.innerHTML = html || '<p style="color: #8b949e; font-size: 0.85rem;">부여된 특별 권한 없음 (기본 공용 도구 사용 가능)</p>';
      } catch (e) {
        permsDiv.innerHTML = '<p style="color: var(--danger); font-size: 0.85rem;">권한 목록 로드 실패</p>';
      }
    }

    function openKeyModal() {
      document.getElementById('key-name').value = '';
      document.getElementById('created-secret-area').style.display = 'none';
      document.getElementById('submit-key-btn').style.display = 'inline-block';
      document.getElementById('key-modal').style.display = 'flex';
    }

    function closeKeyModal() {
      document.getElementById('key-modal').style.display = 'none';
      loadKeys();
    }

    async function createApiKey(e) {
      e.preventDefault();
      const name = document.getElementById('key-name').value.trim();
      if (!name) return;
      try {
        const res = await fetch('/api/v1/keys', {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ name }),
        });
        if (res.ok) {
          const data = await res.json();
          document.getElementById('raw-key-value').textContent = data.plainKey;
          document.getElementById('created-secret-area').style.display = 'block';
          document.getElementById('submit-key-btn').style.display = 'none';
        } else {
          alert('API Key 발급 실패');
        }
      } catch (e) {
        alert('요청 중 오류 발생');
      }
    }

    async function revokeKey(keyId) {
      if (!confirm('정말 이 API Key를 삭제(무효화)하시겠습니까?')) return;
      try {
        const res = await fetch(\`/api/v1/keys/\${keyId}\`, { method: 'DELETE' });
        if (res.ok) {
          loadKeys();
        } else {
          alert('키 삭제 실패');
        }
      } catch (e) {
        alert('요청 중 오류 발생');
      }
    }

    init();
  </script>
</body>
</html>`;
