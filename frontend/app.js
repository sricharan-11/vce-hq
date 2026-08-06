document.addEventListener('DOMContentLoaded', () => {
    // --- State & Auth ---
    let currentTenant = document.getElementById('tenantId').value;
    let currentUser = null;
    let isAdmin = false;

    function getAuthToken() {
        return localStorage.getItem('vce_token');
    }

    async function authFetch(url, options = {}) {
        const headers = {
            ...options.headers
        };
        // Ensure credentials are sent with the fetch request so the HttpOnly cookie is included
        const response = await fetch(url, { ...options, headers, credentials: 'same-origin' });
        if (response.status === 401) {
            handleLogout(); // Auto-logout if token is invalid/expired
        }
        return response;
    }

    function parseJwt(token) {
        try {
            return JSON.parse(atob(token.split('.')[1]));
        } catch (e) {
            return null;
        }
    }

    async function checkAuth() {
        try {
            const resp = await authFetch('/auth/me');
            if (resp.ok) {
                const payload = await resp.json();
                currentUser = payload.username;
                isAdmin = payload.role === 'admin';
                document.getElementById('loginView').style.display = 'none';
                document.querySelector('.app-container').style.display = 'flex';
                if (isAdmin) {
                    document.getElementById('navUsers').style.display = 'flex';
                }
                
                // Initialize Data
                fetchAutomatedReports();
                restoreSession();
                return;
            }
        } catch (e) {
            console.error("Auth check failed", e);
        }
        // Not authenticated
        document.getElementById('loginView').style.display = 'flex';
        document.querySelector('.app-container').style.display = 'none';
        initCloudAuthUI();
    }

    async function initCloudAuthUI() {
        const providers = [
            { key: 'gcp',   endpoint: '/auth/gcp/config',   btnId: 'gcpLoginBtn'   },
            { key: 'azure', endpoint: '/auth/azure/config', btnId: 'azureLoginBtn' },
            { key: 'aws',   endpoint: '/auth/aws/config',   btnId: 'awsLoginBtn'   },
        ];
        let anyEnabled = false;
        await Promise.all(providers.map(async (p) => {
            try {
                const resp = await fetch(p.endpoint);
                if (!resp.ok) return;
                const cfg = await resp.json();
                if (cfg.enabled) {
                    const btn = document.getElementById(p.btnId);
                    if (btn) btn.style.display = 'flex';
                    anyEnabled = true;
                }
            } catch (e) { /* endpoint may 404 — ignore */ }
        }));
        const section = document.getElementById('cloudAuthSection');
        if (section) section.style.display = anyEnabled ? 'block' : 'none';
    }

    document.addEventListener('click', (e) => {
        const btn = e.target && e.target.closest && e.target.closest('.provider-btn');
        if (!btn) return;
        const provider = btn.dataset.provider;
        if (!provider) return;
        const tenantId = (document.getElementById('cloudTenantId').value || '').trim();
        if (!tenantId) {
            document.getElementById('loginError').innerText = 'Enter a tenant ID before cloud sign-in.';
            return;
        }
        window.location.href = `/auth/${provider}/login?tenant_id=` + encodeURIComponent(tenantId);
    });

    // OAuth callback lands us at /ui/?oauth_error=... if it failed. Success sets a cookie and redirects to /ui/
    (function handleOAuthCallbackFragment() {
        const params = new URLSearchParams(window.location.search);
        const errorMsg = params.get('oauth_error');
        if (errorMsg) {
            const el = document.getElementById('loginError');
            if (el) el.innerText = decodeURIComponent(errorMsg);
            history.replaceState(null, '', window.location.pathname);
            return;
        }
        // Always check auth on load to see if a cookie is present
        checkAuth();
    })();

    // --- Login Handling ---
    document.getElementById('loginForm').addEventListener('submit', async (e) => {
        e.preventDefault();
        const username = document.getElementById('username').value;
        const password = document.getElementById('password').value;
        const errorDiv = document.getElementById('loginError');
        
        try {
            const formData = new URLSearchParams();
            formData.append('username', username);
            formData.append('password', password);
            
            const response = await fetch('/auth/login', {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: formData
            });
            
            if (response.ok) {
                // The server sets the HttpOnly cookie upon successful login
                errorDiv.innerText = '';
                checkAuth();
            } else {
                errorDiv.innerText = 'Invalid username or password.';
            }
        } catch (err) {
            errorDiv.innerText = 'Connection failed.';
        }
    });

    async function handleLogout() {
        try {
            await fetch('/auth/logout', { method: 'POST' });
        } catch (e) {
            console.error("Logout request failed", e);
        }
        localStorage.removeItem('vce_session_id');
        currentSessionId = null;
        document.getElementById('loginView').style.display = 'flex';
        document.querySelector('.app-container').style.display = 'none';
    }

    document.getElementById('logoutBtn').addEventListener('click', (e) => {
        e.preventDefault();
        handleLogout();
    });

    // --- Navigation ---
    const navLinks = document.querySelectorAll('.nav-links li');
    const views = document.querySelectorAll('.view');

    navLinks.forEach(link => {
        link.addEventListener('click', () => {
            navLinks.forEach(n => n.classList.remove('active'));
            link.classList.add('active');

            const targetViewId = link.getAttribute('data-view') + 'View';
            views.forEach(v => {
                if (v.id === targetViewId) {
                    v.classList.remove('hidden');
                } else {
                    v.classList.add('hidden');
                }
            });

            const viewId = link.getAttribute('data-view');
            if (viewId === 'vault') {
                loadCredentials();
            } else if (viewId === 'knowledge') {
                fetchKnowledge();
            } else if (viewId === 'finops') {
                fetchFinopsData();
            } else if (viewId === 'users') {
                // Initialize users view
            }
        });
    });

    // --- Tenant Handling ---
    document.getElementById('tenantId').addEventListener('change', (e) => {
        currentTenant = e.target.value;
        if(!document.getElementById('vaultView').classList.contains('hidden')) loadCredentials();
        if(!document.getElementById('finopsView').classList.contains('hidden')) fetchFinopsData();
        fetchAutomatedReports();
    });

    // --- Notification Handling ---
    const notifBtn = document.getElementById('notifBtn');
    const notifDropdown = document.getElementById('notifDropdown');
    const notifBadge = document.getElementById('notifBadge');
    const notifList = document.getElementById('notifList');
    const refreshNotifBtn = document.getElementById('refreshNotifBtn');

    if (notifBtn) {
        notifBtn.addEventListener('click', () => {
            if (notifDropdown.style.display === 'none' || notifDropdown.style.display === '') {
                notifDropdown.style.display = 'block';
                fetchAutomatedReports();
            } else {
                notifDropdown.style.display = 'none';
            }
        });
    }

    if (refreshNotifBtn) {
        refreshNotifBtn.addEventListener('click', () => {
            fetchAutomatedReports();
        });
    }

    document.addEventListener('click', (e) => {
        if (!e.target.closest('.notifications-container')) {
            if (notifDropdown) notifDropdown.style.display = 'none';
        }
    });

    async function fetchAutomatedReports() {
        try {
            const response = await authFetch(`/analyze/reports/automated`, {
                headers: { 'X-Tenant-ID': currentTenant }
            });
            if (response.ok) {
                const reports = await response.json();
                
                if (reports.length > 0) {
                    notifBadge.style.display = 'block';
                    notifBadge.innerText = reports.length;
                    
                    notifList.innerHTML = '';
                    reports.forEach(report => {
                        let icon = 'fa-chart-line';
                        let title = 'FinOps Report';
                        let color = '#3b82f6';
                        
                        if (report.type === 'finops_hourly') {
                            icon = 'fa-bolt';
                            title = 'Hourly Spike Detection';
                            color = '#eab308';
                        } else if (report.type === 'finops_daily') {
                            icon = 'fa-broom';
                            title = 'Daily Waste Cleanup';
                            color = '#22c55e';
                        } else if (report.type === 'finops_monthly') {
                            icon = 'fa-landmark';
                            title = 'Monthly Architecture Review';
                            color = '#ec4899';
                        }
                        
                        notifList.innerHTML += `
                            <div style="padding: 15px; border-bottom: 1px solid #333; cursor: pointer; transition: background 0.2s;" onmouseover="this.style.background='#27272f'" onmouseout="this.style.background='transparent'">
                                <div style="display: flex; align-items: center; margin-bottom: 8px;">
                                    <i class="fa-solid ${icon}" style="color: ${color}; margin-right: 10px; font-size: 1.2rem;"></i>
                                    <strong style="color: white; font-size: 0.95rem;">${DOMPurify.sanitize(title)}</strong>
                                    <span style="margin-left: auto; font-size: 0.75rem; color: #666;">${new Date(report.created_at).toLocaleString()}</span>
                                </div>
                                <div style="color: #a1a1aa; font-size: 0.85rem; line-height: 1.4; display: -webkit-box; -webkit-line-clamp: 3; -webkit-box-orient: vertical; overflow: hidden; text-overflow: ellipsis;">
                                    ${DOMPurify.sanitize(marked.parse(report.summary))}
                                </div>
                            </div>
                        `;
                    });
                } else {
                    notifBadge.style.display = 'none';
                    notifList.innerHTML = '<div style="text-align: center; padding: 20px; color: #666;">No automated reports found.</div>';
                }
            }
        } catch (e) {
            console.error('Failed to fetch automated reports', e);
        }
    }

    // Poll every 60 seconds
    setInterval(fetchAutomatedReports, 60000);
    // Initial fetch
    fetchAutomatedReports();

    // --- New Chat ---
    document.getElementById('newChatBtn').addEventListener('click', () => {
        localStorage.removeItem('vce_session_id');
        currentSessionId = null;
        chatHistory.innerHTML = '';
        appendMessage(`<h2>Welcome to VCE-HQ Swarm</h2><p>I am your autonomous infrastructure operations advisor. You can ask me to analyze alerts, debug issues across Kubernetes, AWS, or GCP, and generate root-cause analyses.</p><p><em>Be sure to add your service accounts to <strong>The Vault</strong> first so I can safely retrieve live logs and metrics during diagnosis!</em></p>`, 'agent');
    });

    // --- Brain Analysis (Chat) ---
    const queryInput = document.getElementById('queryInput');
    const sendQueryBtn = document.getElementById('sendQueryBtn');
    const chatHistory = document.getElementById('chatHistory');
    let currentSessionId = localStorage.getItem('vce_session_id') || null;

    // Restore chat history on page load
    async function restoreSession() {
        if (!currentSessionId) return;
        try {
            const response = await authFetch(`/analyze/sessions/${currentSessionId}/history`, {
                headers: { 'X-Tenant-ID': currentTenant }
            });
            if (response.ok) {
                const turns = await response.json();
                if (turns.length === 0) return;
                // Clear the welcome message before restoring
                chatHistory.innerHTML = '';
                turns.forEach(turn => {
                    // Skip empty or whitespace-only turns
                    const trimmed = (turn.content || '').trim();
                    if (!trimmed) return;
                    
                    // Skip internal router/agent chatter — only show user queries and final responses
                    if (trimmed.startsWith('[ROUTER')) return;
                    if (trimmed.startsWith('[OS ENGINEER')) return;
                    if (trimmed.startsWith('[CLOUD ENGINEER')) return;
                    if (trimmed.startsWith('[FINOPS')) return;
                    
                    if (turn.content.startsWith('[USER QUERY]: ')) {
                        appendMessage(turn.content.replace('[USER QUERY]: ', ''), 'user');
                    } else {
                        let parsedHTML = turn.content;
                        if (typeof marked !== 'undefined') {
                            parsedHTML = marked.parse(turn.content);
                        }
                        appendMessage(parsedHTML, 'agent');
                    }
                });
            } else {
                // Session not found — clear stale reference
                currentSessionId = null;
                localStorage.removeItem('vce_session_id');
            }
        } catch(e) {
            console.error('Failed to restore session', e);
        }
    }
    restoreSession();

    async function sendQuery() {
        const query = queryInput.value.trim();
        if(!query) return;

        // Add User Message
        appendMessage(query, 'user');
        queryInput.value = '';

        // Add Loading Indicator
        const loadingId = 'loading-' + Date.now();
        const loadingHTML = `<div class="dot-flashing"></div><span style="margin-left:24px">Agent Swarm Analyzing...</span>`;
        appendMessage(loadingHTML, 'loading', loadingId);

        try {
            const body = { query: query };
            if (currentSessionId) body.session_id = currentSessionId;

            const response = await authFetch('/analyze/', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-Tenant-ID': currentTenant
                },
                body: JSON.stringify(body)
            });

            const data = await response.json();
            
            // Remove loading
            const loadingEl = document.getElementById(loadingId);
            if (loadingEl) loadingEl.remove();

            // Track session for multi-turn conversations
            if (data.session_id) {
                currentSessionId = data.session_id;
                localStorage.setItem('vce_session_id', currentSessionId);
            }

            if(response.ok) {
                // Parse markdown to HTML
                let parsedAnalysis = data.analysis || "No analysis returned.";
                if (typeof marked !== 'undefined') {
                    parsedAnalysis = marked.parse(parsedAnalysis);
                }
                
                let responseHTML = parsedAnalysis;
                // Only show the security flag banner for genuine failures/warnings
                const hasRealFlags = data.security_flags && data.security_flags.length > 0
                    && data.security_flags.some(f => !f.toLowerCase().startsWith('passed'));
                if(hasRealFlags) {
                    responseHTML += `<div style="margin-top: 16px; padding: 12px; background: rgba(239, 68, 68, 0.1); border-left: 4px solid var(--danger); border-radius: 4px;">
                        <strong><i class="fa-solid fa-shield-halved"></i> Security Flags:</strong>
                        <ul style="margin-top: 8px;">${data.security_flags.filter(f => !f.toLowerCase().startsWith('passed')).map(f => `<li>${f}</li>`).join('')}</ul>
                    </div>`;
                }

                appendMessage(responseHTML, 'agent');
            } else {
                appendMessage(`Error: ${data.detail || 'Failed to analyze request.'}`, 'agent');
            }
        } catch (error) {
            console.error(error);
            const loadingEl = document.getElementById(loadingId);
            if (loadingEl) loadingEl.remove();
            appendMessage(`Error: Could not connect to server or parse response.`, 'agent');
        }
    }

    sendQueryBtn.addEventListener('click', sendQuery);
    queryInput.addEventListener('keydown', (e) => {
        if(e.key === 'Enter' && !e.shiftKey) {
            e.preventDefault();
            sendQuery();
        }
    });

    function appendMessage(content, type, id = null) {
        const div = document.createElement('div');
        div.className = `message ${type}`;
        if(id) div.id = id;
        
        if (type === 'user') {
            div.textContent = content; // Safe text rendering
        } else if (type === 'loading') {
            div.innerHTML = content; // Trusted HTML string
        } else {
            // Content is parsed HTML for agent, sanitize it!
            if (typeof DOMPurify !== 'undefined') {
                div.innerHTML = DOMPurify.sanitize(content);
            } else {
                div.textContent = content; // Fallback safely
            }
        }

        chatHistory.appendChild(div);
        chatHistory.scrollTop = chatHistory.scrollHeight;
    }

    // --- The Vault (Credentials) ---
    const addCredentialForm = document.getElementById('addCredentialForm');
    const credentialList = document.getElementById('credentialList');
    const refreshCredsBtn = document.getElementById('refreshCredsBtn');

    refreshCredsBtn.addEventListener('click', loadCredentials);

    async function loadCredentials() {
        if(!currentTenant) return;
        
        try {
            const response = await authFetch('/credentials/', {
                headers: { 'X-Tenant-ID': currentTenant }
            });
            
            if(response.ok) {
                const creds = await response.json();
                renderCredentials(creds);
            }
        } catch (error) {
            console.error("Failed to load credentials", error);
        }
    }

    function renderCredentials(creds) {
        credentialList.innerHTML = '';
        if(creds.length === 0) {
            credentialList.innerHTML = '<li style="text-align:center; color: var(--text-muted); padding: 20px;">No credentials securely stored.</li>';
            return;
        }

        creds.forEach(cred => {
            const li = document.createElement('li');
            li.className = 'credential-item';
            
            const statusBadge = cred.inventory_status === 'capturing'
                ? `<span class="inventory-badge capturing"><i class="fa-solid fa-rotate fa-spin"></i> Capturing</span>`
                : cred.inventory_status === 'ready'
                ? `<span class="inventory-badge ready"><i class="fa-solid fa-circle-check"></i> Inventory Ready</span>`
                : `<span class="inventory-badge unknown"><i class="fa-solid fa-circle-question"></i> No Inventory</span>`;
            
            li.innerHTML = `
                <div class="cred-info">
                    <strong>${DOMPurify.sanitize(cred.name)}</strong>
                    <span>${DOMPurify.sanitize(cred.provider).toUpperCase()} &bull; Added ${new Date(cred.created_at).toLocaleDateString()}</span>
                    <div style="margin-top:6px">${statusBadge}</div>
                </div>
                <div class="cred-actions">
                    <button onclick="refreshInventory('${CSS.escape(cred.name)}')" title="Re-capture Inventory" style="background:rgba(59,130,246,0.1);color:var(--accent);margin-right:6px">
                        <i class="fa-solid fa-rotate-right"></i>
                    </button>
                    <button onclick="deleteCredential('${CSS.escape(cred.name)}')" title="Delete Credential">
                        <i class="fa-solid fa-trash"></i>
                    </button>
                </div>
            `;
            credentialList.appendChild(li);
        });
    }

    addCredentialForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        
        const name = document.getElementById('credName').value;
        const provider = document.getElementById('credProvider').value;
        const value = document.getElementById('credValue').value;
        const submitBtn = addCredentialForm.querySelector('button[type="submit"]');
        submitBtn.disabled = true;
        submitBtn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Storing...';

        try {
            const response = await authFetch('/credentials/', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-Tenant-ID': currentTenant
                },
                body: JSON.stringify({
                    name: name,
                    provider: provider,
                    credential_value: value
                })
            });

            if(response.ok) {
                const data = await response.json();
                addCredentialForm.reset();
                loadCredentials();
                // Show inventory capturing toast
                showToast(`✅ Credential stored! Inventory sweep started for ${provider.toUpperCase()} — this may take a minute.`, 6000);
            } else {
                const err = await response.json();
                alert(`Error: ${err.detail || 'Failed to add credential'}`);
            }
        } catch(error) {
            alert('Failed to connect to server.');
        } finally {
            submitBtn.disabled = false;
            submitBtn.innerHTML = 'Securely Store';
        }
    });

    window.deleteCredential = async function(name) {
        if(!confirm(`Are you sure you want to securely delete '${name}'?`)) return;

        try {
            const response = await authFetch(`/credentials/${encodeURIComponent(name)}`, {
                method: 'DELETE',
                headers: { 'X-Tenant-ID': currentTenant }
            });

            if(response.ok) {
                loadCredentials();
                showToast(`🗑️ Credential '${name}' deleted.`);
            }
        } catch(error) {
            console.error("Failed to delete", error);
        }
    };

    window.refreshInventory = async function(name) {
        showToast(`🔄 Re-capturing inventory for '${name}'...`, 4000);
        try {
            const response = await authFetch(`/credentials/${encodeURIComponent(name)}/refresh-inventory`, {
                method: 'POST',
                headers: { 'X-Tenant-ID': currentTenant }
            });
            if(response.ok) {
                showToast(`✅ Inventory sweep started for '${name}'. Check back in a minute.`, 5000);
                loadCredentials();
            }
        } catch(error) {
            console.error("Failed to refresh inventory", error);
        }
    };

    function showToast(message, duration = 3000) {
        let toast = document.getElementById('vce-toast');
        if(!toast) {
            toast = document.createElement('div');
            toast.id = 'vce-toast';
            toast.style.cssText = `
                position:fixed; bottom:24px; left:50%; transform:translateX(-50%);
                background:rgba(30,35,48,0.95); color:#e2e8f0; padding:14px 28px;
                border-radius:12px; font-size:14px; border:1px solid rgba(255,255,255,0.1);
                backdrop-filter:blur(12px); z-index:9999; max-width:480px;
                box-shadow: 0 8px 32px rgba(0,0,0,0.4); transition: opacity 0.3s;
            `;
            document.body.appendChild(toast);
        }
        toast.textContent = message;
        toast.style.opacity = '1';
        clearTimeout(toast._timeout);
        toast._timeout = setTimeout(() => { toast.style.opacity = '0'; }, duration);
    }
    
    // --- Knowledge Library (LTM) ---
    const ingestKnowledgeForm = document.getElementById('ingestKnowledgeForm');
    
    if (ingestKnowledgeForm) {
        ingestKnowledgeForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            
            const docName = document.getElementById('docName').value;
            const category = document.getElementById('docCategory').value;
            const content = document.getElementById('docContent').value;
            
            const submitBtn = ingestKnowledgeForm.querySelector('button[type="submit"]');
            submitBtn.disabled = true;
            submitBtn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Ingesting...';
            
            try {
                const response = await authFetch('/knowledge/ingest', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-Tenant-ID': currentTenant
                    },
                    body: JSON.stringify({
                        document_name: docName,
                        category: category,
                        content: content
                    })
                });

                if(response.ok) {
                    const data = await response.json();
                    ingestKnowledgeForm.reset();
                    showToast(`✅ Success: ${data.message}`, 5000);
                    fetchKnowledge();
                } else {
                    const err = await response.json();
                    alert(`Error: ${err.detail || 'Failed to ingest document'}`);
                }
            } catch(error) {
                alert('Failed to connect to server.');
            } finally {
                submitBtn.disabled = false;
                submitBtn.innerHTML = '<i class="fa-solid fa-upload"></i> Ingest to LTM';
            }
        });
    }

    const refreshKnowledgeBtn = document.getElementById('refreshKnowledgeBtn');
    if (refreshKnowledgeBtn) {
        refreshKnowledgeBtn.addEventListener('click', fetchKnowledge);
    }
    
    const knowledgeTableBody = document.querySelector('#knowledgeTable tbody');
    if (knowledgeTableBody) {
        knowledgeTableBody.addEventListener('click', (e) => {
            const btn = e.target.closest('.delete-doc-btn');
            if (btn) {
                const docName = btn.getAttribute('data-doc-name');
                if (docName) {
                    deleteKnowledge(docName);
                }
            }
        });
    }

    async function fetchKnowledge() {
        const tbody = document.querySelector('#knowledgeTable tbody');
        if (!tbody) return;
        
        tbody.innerHTML = '<tr><td colspan="5" style="text-align: center;"><i class="fa-solid fa-spinner fa-spin"></i> Loading...</td></tr>';
        
        try {
            const response = await authFetch(`/knowledge/`, {
                headers: { 'X-Tenant-ID': currentTenant }
            });
            
            if (response.ok) {
                const docs = await response.json();
                tbody.innerHTML = '';
                
                if (docs.length === 0) {
                    tbody.innerHTML = '<tr><td colspan="5" style="text-align: center; color: var(--text-secondary);">No documents ingested yet.</td></tr>';
                    return;
                }
                
                docs.forEach(doc => {
                    const tr = document.createElement('tr');
                    
                    const date = new Date(doc.created_at);
                    
                    tr.innerHTML = `
                        <td style="font-family: monospace;">${DOMPurify.sanitize(doc.document_name)}</td>
                        <td><span class="status-badge" style="background: rgba(139, 92, 246, 0.2); color: #c4b5fd;">${DOMPurify.sanitize(doc.category)}</span></td>
                        <td>${doc.chunks}</td>
                        <td>${date.toLocaleString()}</td>
                        <td>
                            <button class="btn-danger btn-small delete-doc-btn" data-doc-name="${DOMPurify.sanitize(doc.document_name).replace(/"/g, '&quot;')}" title="Delete">
                                <i class="fa-solid fa-trash"></i>
                            </button>
                        </td>
                    `;
                    tbody.appendChild(tr);
                });
            }
        } catch (error) {
            tbody.innerHTML = '<tr><td colspan="5" style="text-align: center; color: #ef4444;">Failed to load documents</td></tr>';
        }
    }

    window.deleteKnowledge = async function(docName) {
        if (!confirm(`Are you sure you want to delete '${docName}' from the LTM? This will remove all its chunks.`)) {
            return;
        }
        
        try {
            const response = await authFetch(`/knowledge/${encodeURIComponent(docName)}`, {
                method: 'DELETE',
                headers: { 'X-Tenant-ID': currentTenant }
            });
            
            if (response.ok) {
                showToast(`✅ Deleted ${docName}`);
                fetchKnowledge();
            } else {
                const err = await response.json();
                alert(`Error: ${err.detail || 'Failed to delete'}`);
            }
        } catch (error) {
            alert('Failed to connect to server.');
        }
    };
    
    // --- FinOps Token Usage ---
    let finopsData = null;
    let currentFinopsPeriod = 'day';
    
    const refreshFinopsBtn = document.getElementById('refreshFinopsBtn');
    if (refreshFinopsBtn) {
        refreshFinopsBtn.addEventListener('click', fetchFinopsData);
    }
    
    const finopsTabs = document.querySelectorAll('.finops-tabs .tab-btn');
    finopsTabs.forEach(tab => {
        tab.addEventListener('click', (e) => {
            finopsTabs.forEach(t => t.classList.remove('active'));
            e.target.classList.add('active');
            currentFinopsPeriod = e.target.getAttribute('data-period');
            renderFinopsData();
        });
    });

    async function fetchFinopsData() {
        if (!currentTenant) return;
        
        try {
            const response = await authFetch('/finops/token-usage', {
                headers: { 'X-Tenant-ID': currentTenant }
            });
            
            if (response.ok) {
                finopsData = await response.json();
                renderFinopsData();
            } else {
                console.error("Failed to fetch finops data");
            }
        } catch (error) {
            console.error("Error fetching finops data", error);
        }
    }

    function renderFinopsData() {
        if (!finopsData) return;
        
        const periodData = finopsData[currentFinopsPeriod];
        if (!periodData) return;
        
        // Render Metric Grid
        const grid = document.getElementById('tokenMetricsGrid');
        grid.innerHTML = `
            <div class="card" style="text-align: center;">
                <h4 style="color: var(--text-muted); margin-bottom: 5px;">Total Tokens</h4>
                <div style="font-size: 2rem; font-weight: 700; color: var(--text-primary);">${periodData.total_tokens.toLocaleString()}</div>
            </div>
            <div class="card" style="text-align: center;">
                <h4 style="color: var(--text-muted); margin-bottom: 5px;">Prompt Tokens</h4>
                <div style="font-size: 2rem; font-weight: 700; color: var(--accent);">${periodData.prompt_tokens.toLocaleString()}</div>
            </div>
            <div class="card" style="text-align: center;">
                <h4 style="color: var(--text-muted); margin-bottom: 5px;">Completion Tokens</h4>
                <div style="font-size: 2rem; font-weight: 700; color: var(--success);">${periodData.completion_tokens.toLocaleString()}</div>
            </div>
            <div class="card" style="text-align: center;">
                <h4 style="color: var(--text-muted); margin-bottom: 5px;">Reasoning Tokens</h4>
                <div style="font-size: 2rem; font-weight: 700; color: var(--warning);">${periodData.reasoning_tokens.toLocaleString()}</div>
            </div>
        `;
        
        // Render Agent Breakdown Table
        const tbody = document.querySelector('#agentTokensTable tbody');
        tbody.innerHTML = '';
        
        const byAgent = periodData.by_agent;
        if (Object.keys(byAgent).length === 0) {
            tbody.innerHTML = '<tr><td colspan="5" style="text-align: center; color: var(--text-secondary);">No token usage recorded for this period.</td></tr>';
            return;
        }
        
        for (const [agent, stats] of Object.entries(byAgent)) {
            const tr = document.createElement('tr');
            tr.innerHTML = `
                <td style="font-weight: 600; color: var(--accent);"><i class="fa-solid fa-robot" style="margin-right: 8px;"></i>${agent}</td>
                <td>${stats.prompt_tokens.toLocaleString()}</td>
                <td>${stats.completion_tokens.toLocaleString()}</td>
                <td>${stats.reasoning_tokens.toLocaleString()}</td>
                <td style="font-weight: bold;">${stats.total_tokens.toLocaleString()}</td>
            `;
            tbody.appendChild(tr);
        }
    }

    // Initial welcome message
    appendMessage(`<h2>Welcome to VCE-HQ Swarm</h2><p>I am your autonomous infrastructure operations advisor. You can ask me to analyze alerts, debug issues across Kubernetes, AWS, or GCP, and generate root-cause analyses.</p><p><em>Be sure to add your service accounts to <strong>The Vault</strong> first so I can safely retrieve live logs and metrics during diagnosis!</em></p>`, 'agent');

    // --- Users & Access ---
    document.getElementById('createUserForm').addEventListener('submit', async (e) => {
        e.preventDefault();
        const username = document.getElementById('newUsername').value;
        const password = document.getElementById('newPassword').value;
        const role = document.getElementById('newRole').value;
        const statusDiv = document.getElementById('createUserStatus');
        const submitBtn = e.target.querySelector('button');
        
        submitBtn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Creating...';
        
        try {
            const response = await authFetch('/auth/users', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-Tenant-ID': currentTenant
                },
                body: JSON.stringify({ username, password, role })
            });
            
            if (response.ok) {
                statusDiv.style.color = '#10b981';
                statusDiv.innerText = `User '${username}' created successfully!`;
                e.target.reset();
            } else {
                const data = await response.json();
                statusDiv.style.color = '#ef4444';
                statusDiv.innerText = data.detail || 'Failed to create user.';
            }
        } catch (err) {
            statusDiv.style.color = '#ef4444';
            statusDiv.innerText = 'Connection failed.';
        } finally {
            submitBtn.innerHTML = 'Create User';
        }
    });

    // Check auth on load
    checkAuth();
});
