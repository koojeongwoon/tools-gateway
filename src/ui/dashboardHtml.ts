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
    
    .list-item { display: flex; justify-content: space-between; align-items: center; padding: 0.9rem; background: var(--bg); border: 1px solid var(--border); border-radius: 6px; margin-bottom: 0.6rem; }
    .list-info h4 { color: var(--text-bright); font-size: 0.95rem; }
    .list-info p { font-size: 0.75rem; color: #8b949e; margin-top: 0.2rem; }
    .code-badge { font-family: monospace; background: var(--tag-bg); padding: 0.2rem 0.4rem; border-radius: 4px; color: var(--accent); }
    
    .modal { display: none; position: fixed; inset: 0; background: rgba(0,0,0,0.7); justify-content: center; align-items: center; padding: 1rem; z-index: 1000; }
    .modal-content { background: var(--card-bg); border: 1px solid var(--border); border-radius: 8px; max-width: 480px; width: 100%; padding: 1.5rem; }
    .modal-content h3 { color: var(--text-bright); margin-bottom: 1rem; }
    .input-group { margin-bottom: 1rem; display: flex; flex-direction: column; gap: 0.4rem; }
    .input-group label { font-size: 0.85rem; color: #8b949e; }
    .input-group input, .input-group select { background: var(--bg); border: 1px solid var(--border); color: var(--text-bright); padding: 0.6rem; border-radius: 6px; font-size: 0.9rem; }
    .input-group input:focus, .input-group select:focus { outline: none; border-color: var(--accent); }
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

    <div id="dashboard-content" style="display: flex; flex-direction: column; gap: 1.5rem;">
            <!-- 🤖 AI Credentials (Codex OAuth / OpenAI / Embedding Keys) -->
      <section class="card">
        <h2>
          <span>🤖 AI 자격증명 & Codex OAuth 연동 (마이페이지)</span>
          <button class="btn btn-outline" onclick="loadAiCredentials()">🔄 새로고침</button>
        </h2>
        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); gap: 1rem; margin-top: 1rem;">
          
          <!-- Codex OAuth Card -->
          <div style="background: var(--bg); border: 1px solid var(--border); border-radius: 6px; padding: 1rem; display: flex; flex-direction: column; justify-content: space-between; gap: 0.8rem;">
            <div>
              <div style="display: flex; justify-content: space-between; align-items: center;">
                <h4 style="font-size: 0.95rem; color: var(--text-bright);">OpenAI Codex OAuth</h4>
                <span id="codex-status" style="font-size: 0.75rem; padding: 0.2rem 0.5rem; border-radius: 12px; font-weight: bold; background: rgba(248, 81, 73, 0.15); color: var(--danger); border: 1px solid rgba(248, 81, 73, 0.4);">확인 중...</span>
              </div>
              <p style="font-size: 0.8rem; color: #8b949e; margin-top: 0.4rem;">에이전트 코드 추론 및 도구 호출 전용 OAuth 세션</p>
            </div>
            <div id="codex-actions">
              <button class="btn btn-primary" style="width: 100%;" onclick="startCodexLink()">🔗 OpenAI 계정 연동하기</button>
            </div>
          </div>

          <!-- OpenAI API Key Card -->
          <div style="background: var(--bg); border: 1px solid var(--border); border-radius: 6px; padding: 1rem; display: flex; flex-direction: column; justify-content: space-between; gap: 0.8rem;">
            <div>
              <div style="display: flex; justify-content: space-between; align-items: center;">
                <h4 style="font-size: 0.95rem; color: var(--text-bright);">OpenAI API Key (벡터 임베딩 & 완성)</h4>
                <span id="openai-status" style="font-size: 0.75rem; padding: 0.2rem 0.5rem; border-radius: 12px; font-weight: bold; background: rgba(248, 81, 73, 0.15); color: var(--danger); border: 1px solid rgba(248, 81, 73, 0.4);">미등록</span>
              </div>
              <p id="openai-hint" style="font-size: 0.8rem; color: #8b949e; margin-top: 0.4rem;">지식베이스/도구 벡터 임베딩 및 인덱싱 처리용 API 키 (sk-...)</p>
            </div>
            <button class="btn btn-outline" style="width: 100%;" onclick="openKeyInputModal('OPENAI_API_KEY', 'OpenAI API Key')">🔑 API Key 설정</button>
          </div>



        </div>
      </section>

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

      <!-- Custom MCP Upstreams Section (Phase 4) -->
      <section class="card">
        <h2>
          🔌 내 커스텀 MCP 서버 등록
          <button class="btn btn-primary" onclick="openUpstreamModal()">+ 새 MCP 서버 등록</button>
        </h2>
        <p style="font-size: 0.8rem; color: #8b949e; margin-bottom: 0.8rem;">
          개인 Notion, 사내 사설 MCP 등을 등록하면 게이트웨이가 토큰을 안전하게 암호화(AES-256-GCM) 보관하고 통합 프록시합니다.
        </p>
        <div id="upstreams-list" style="margin-top: 1rem;">
          <p style="color: #8b949e; font-size: 0.85rem;">등록된 커스텀 MCP 서버가 없습니다.</p>
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

  <!-- Custom MCP Upstream Modal -->
  <div id="upstream-modal" class="modal">
    <div class="modal-content">
      <h3>🔌 새 커스텀 MCP 서버 등록</h3>
      <form id="upstream-form" onsubmit="createUpstream(event)">
        <div class="input-group">
          <label for="ups-prefix">도구 접두사 (Tool Prefix)</label>
          <input type="text" id="ups-prefix" placeholder="예: my_notion, internal_db (소문자/언더바)" pattern="^[a-z][a-z0-9_]{0,49}$" required>
        </div>
        <div class="input-group">
          <label for="ups-url">엔드포인트 URL</label>
          <input type="url" id="ups-url" placeholder="https://my-mcp.company.com/mcp" required>
        </div>
        <div class="input-group">
          <label for="ups-auth-type">인증 방식</label>
          <select id="ups-auth-type" onchange="toggleAuthValueInput()">
            <option value="bearer">Bearer Token</option>
            <option value="api_key">API Key</option>
            <option value="none">인증 없음 (None)</option>
          </select>
        </div>
        <div class="input-group" id="ups-auth-val-group">
          <label for="ups-auth-val">인증 시크릿 (토큰 / 키) - AES-256-GCM 암호화 보관</label>
          <input type="password" id="ups-auth-val" placeholder="비밀 토큰 입력">
        </div>
        <div class="input-group">
          <label for="ups-desc">설명 (선택)</label>
          <input type="text" id="ups-desc" placeholder="예: 개인 노션 워크스페이스 문서 도구">
        </div>
        <div class="modal-actions">
          <button type="button" class="btn btn-outline" onclick="closeUpstreamModal()">닫기</button>
          <button type="submit" class="btn btn-primary">등록하기</button>
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
            loadUpstreams();
            loadPermissions();
            loadAiCredentials();
            document.getElementById('dashboard-content').style.display = 'flex';
            return;
          }
        }
      } catch (e) {}
      console.warn('Keeping dashboard visible');
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
      // IAM 표준 테넌트 로그아웃(/portal/tenants/{tenantId}/signout?clientId={clientId}) 호출 -> 세션 파기 후 테넌트 포털로 자동 복귀
      location.href = 'https://auth.snappytory.com/portal/tenants/tools-gateway/signout?clientId=tools-gateway';
    }

        // ================= AI Credentials Functions =================
    let pollInterval = null;
    let currentVerifyUrl = "";

    async function loadAiCredentials() {
      try {
        const res = await fetch('/api/v1/ai-credentials/bundle');
        if (!res.ok) return;
        const bundle = await res.json();
        
        // Codex
        const codexStatus = document.getElementById('codex-status');
        const codexActions = document.getElementById('codex-actions');
        if (bundle.codex && bundle.codex.linked) {
          codexStatus.textContent = "🟢 연동됨";
          codexStatus.className = "status-badge linked";
          codexActions.innerHTML = '<button class="btn btn-danger" style="width: 100%;" onclick="unlinkCodex()">연동 해제</button>';
        } else {
          codexStatus.textContent = "🔴 미연동";
          codexStatus.className = "status-badge unlinked";
          codexActions.innerHTML = '<button class="btn btn-primary" style="width: 100%;" onclick="startCodexLink()">🔗 OpenAI 계정 연동하기</button>';
        }

        // OpenAI Key
        const openaiStatus = document.getElementById('openai-status');
        const openaiHint = document.getElementById('openai-hint');
        if (bundle.openai_api_key && bundle.openai_api_key.configured) {
          openaiStatus.textContent = "🟢 등록됨";
          openaiStatus.className = "status-badge linked";
          openaiHint.textContent = "등록된 키: " + (bundle.openai_api_key.masked_hint || "sk-***");
        } else {
          openaiStatus.textContent = "🔴 미등록";
          openaiStatus.className = "status-badge unlinked";
          openaiHint.textContent = "범용 LLM 완성 API 키 (sk-...)";
        }

        // Sync embedding key automatically if openai key is set
        if (bundle.openai_api_key && bundle.openai_api_key.configured && (!bundle.embedding_api_key || !bundle.embedding_api_key.configured)) {
          // Both share the same central OpenAI credential
        }
      } catch (e) {
        console.error("Failed to load AI bundle", e);
      }
    }

    async function startCodexLink() {
      try {
        const res = await fetch('/api/v1/ai-credentials/codex/device/start', { method: 'POST' });
        if (!res.ok) {
          alert("Device Flow 시작 실패");
          return;
        }
        const initData = await res.json();
        document.getElementById('device-user-code').textContent = initData.user_code;
        currentVerifyUrl = initData.verification_uri_complete || initData.verification_uri;
        document.getElementById('codex-modal').style.display = 'flex';
        
        if (pollInterval) clearInterval(pollInterval);
        pollInterval = setInterval(async () => {
          try {
            const checkRes = await fetch('/api/v1/ai-credentials/codex/device/check', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({
                deviceAuthId: initData.device_auth_id || initData.device_code,
                userCode: initData.user_code
              })
            });
            if (checkRes.ok) {
              clearInterval(pollInterval);
              document.getElementById('device-polling-status').textContent = "🎉 연동 성공!";
              document.getElementById('device-polling-status').style.color = "var(--success)";
              setTimeout(() => {
                closeCodexModal();
                loadAiCredentials();
              }, 1200);
            }
          } catch (e) {}
        }, 3000);
      } catch (err) {
        alert("Codex 연동 시작 에러: " + err);
      }
    }

    function copyUserCode() {
      const code = document.getElementById('device-user-code').textContent;
      navigator.clipboard.writeText(code);
      alert("인증 코드 " + code + " 가 클립보드에 복사되었습니다!");
    }

    function openVerifyUri() {
      if (currentVerifyUrl) {
        window.open(currentVerifyUrl, '_blank');
      }
    }

    function closeCodexModal() {
      if (pollInterval) clearInterval(pollInterval);
      document.getElementById('codex-modal').style.display = 'none';
    }

    async function unlinkCodex() {
      if (!confirm("정말 Codex 연동을 해제하시겠습니까?")) return;
      await fetch('/api/v1/ai-credentials/keys/CODEX_OAUTH', { method: 'DELETE' });
      loadAiCredentials();
    }

    function openKeyInputModal(provider, title) {
      document.getElementById('key-provider').value = provider;
      document.getElementById('key-input-title').textContent = title + " 설정";
      document.getElementById('key-val').value = "";
      document.getElementById('key-input-modal').style.display = 'flex';
    }

    function closeKeyInputModal() {
      document.getElementById('key-input-modal').style.display = 'none';
    }

    async function saveAiKey(e) {
      e.preventDefault();
      const provider = document.getElementById('key-provider').value;
      const apiKey = document.getElementById('key-val').value;
      try {
        const res = await fetch('/api/v1/ai-credentials/keys', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ provider, apiKey })
        });
        if (res.ok) {
          closeKeyInputModal();
          loadAiCredentials();
        } else {
          alert("키 저장 실패");
        }
      } catch (err) {
        alert("키 저장 에러: " + err);
      }
    }

    async function deleteAiKey() {
      const provider = document.getElementById('key-provider').value;
      if (!confirm("정말 이 API Key를 삭제하시겠습니까?")) return;
      await fetch('/api/v1/ai-credentials/keys/' + provider, { method: 'DELETE' });
      closeKeyInputModal();
      loadAiCredentials();
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
          <div class="list-item">
            <div class="list-info">
              <h4>\${k.name} <span class="code-badge">\${k.key_prefix}...</span></h4>
              <p>생성일: \${new Date(k.created_at).toLocaleDateString()} | 스코프: \${k.allowed_scopes.join(', ')}</p>
            </div>
            <button class="btn btn-danger" onclick="revokeKey('\${k.id}')">삭제</button>
          </div>
        \`).join('');
      } catch (e) {
        listDiv.innerHTML = '<p style="color: var(--danger); font-size: 0.85rem;">키 목록 로드 실패</p>';
      }
    }

    async function loadUpstreams() {
      const listDiv = document.getElementById('upstreams-list');
      try {
        const res = await fetch('/api/v1/upstreams');
        if (!res.ok) return;
        const upstreams = await res.json();
        if (upstreams.length === 0) {
          listDiv.innerHTML = '<p style="color: #8b949e; font-size: 0.85rem;">등록된 커스텀 MCP 서버가 없습니다.</p>';
          return;
        }
        listDiv.innerHTML = upstreams.map(u => \`
          <div class="list-item">
            <div class="list-info">
              <h4>⚡ prefix: <span class="code-badge">\${u.toolPrefix}.*</span> \${u.description ? ' - ' + u.description : ''}</h4>
              <p>엔드포인트: \${u.endpointUrl} | 인증: \${u.authType} | 등록일: \${new Date(u.createdAt).toLocaleDateString()}</p>
            </div>
            <button class="btn btn-danger" onclick="deleteUpstream('\${u.id}')">삭제</button>
          </div>
        \`).join('');
      } catch (e) {
        listDiv.innerHTML = '<p style="color: var(--danger); font-size: 0.85rem;">MCP 서버 목록 로드 실패</p>';
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
          html += '<div style="margin-bottom: 0.8rem;"><strong>허용된 공용 MCP 도구:</strong><br>';
          html += data.tools.map(t => \`<span class="tag">⚡ \${t}</span>\`).join('');
          html += '</div>';
        }
        if (data.services && data.services.length > 0) {
          html += '<div><strong>서비스 권한:</strong><br>';
          html += data.services.map(s => \`<span class="tag">\${s.service_name} (\${s.allowed_actions.join(', ')})</span>\`).join('');
          html += '</div>';
        }
        permsDiv.innerHTML = html || '<p style="color: #8b949e; font-size: 0.85rem;">기본 공용 도구 사용 가능</p>';
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

    function openUpstreamModal() {
      document.getElementById('upstream-form').reset();
      toggleAuthValueInput();
      document.getElementById('upstream-modal').style.display = 'flex';
    }

    function closeUpstreamModal() {
      document.getElementById('upstream-modal').style.display = 'none';
      loadUpstreams();
    }

    function toggleAuthValueInput() {
      const type = document.getElementById('ups-auth-type').value;
      document.getElementById('ups-auth-val-group').style.display = type === 'none' ? 'none' : 'flex';
    }

    async function createUpstream(e) {
      e.preventDefault();
      const toolPrefix = document.getElementById('ups-prefix').value.trim();
      const endpointUrl = document.getElementById('ups-url').value.trim();
      const authType = document.getElementById('ups-auth-type').value;
      const authValue = document.getElementById('ups-auth-val').value.trim();
      const description = document.getElementById('ups-desc').value.trim();

      try {
        const res = await fetch('/api/v1/upstreams', {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({
            toolPrefix,
            endpointUrl,
            authType,
            authValue: authType !== 'none' ? authValue : undefined,
            description: description || undefined,
          }),
        });
        if (res.ok) {
          closeUpstreamModal();
        } else {
          const err = await res.json();
          alert('MCP 서버 등록 실패: ' + (err.error || '알 수 없는 오류'));
        }
      } catch (e) {
        alert('요청 중 오류 발생');
      }
    }

    async function deleteUpstream(id) {
      if (!confirm('정말 이 커스텀 MCP 서버를 삭제하시겠습니까?')) return;
      try {
        const res = await fetch(\`/api/v1/upstreams/\${id}\`, { method: 'DELETE' });
        if (res.ok) {
          loadUpstreams();
        } else {
          alert('MCP 서버 삭제 실패');
        }
      } catch (e) {
        alert('요청 중 오류 발생');
      }
    }

    init();
  </script>
</body>
</html>`;
