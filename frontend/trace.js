document.addEventListener('DOMContentLoaded', () => {
    fetchRequests();
});

async function fetchRequests() {
    const tenantId = document.getElementById('tenantInput').value || 'default';
    try {
        const response = await fetch('/api/trace/requests', {
            headers: { 'X-Tenant-ID': tenantId }
        });
        const data = await response.json();
        if (response.ok) {
            renderSidebar(data.requests);
        } else {
            document.getElementById('requestList').innerHTML = `<div style="padding: 20px; color: #ff7b72;">${escapeHtml(data.detail || 'Failed to load')}</div>`;
        }
    } catch (error) {
        console.error("Error fetching requests:", error);
        document.getElementById('requestList').innerHTML = `<div style="padding: 20px; color: #ff7b72;">Failed to load requests</div>`;
    }
}

function renderSidebar(requests) {
    const requestList = document.getElementById('requestList');
    requestList.innerHTML = '';

    if (!requests || requests.length === 0) {
        requestList.innerHTML = `<div style="padding: 20px; color: #8b949e;">No requests found.</div>`;
        return;
    }

    requests.forEach(req => {
        const div = document.createElement('div');
        div.className = 'request-item';
        div.onclick = () => loadTrace(req.request_id, div);
        
        const date = new Date(req.last_activity);
        
        div.innerHTML = `
            <div class="request-id">${req.request_id.split('-')[0]}...</div>
            <div class="request-time">${date.toLocaleString()}</div>
        `;
        requestList.appendChild(div);
    });
}

async function loadTrace(requestId, element) {
    // UI active state
    document.querySelectorAll('.request-item').forEach(el => el.classList.remove('active'));
    if (element) element.classList.add('active');

    document.getElementById('trace-header').innerText = `Trace: ${requestId}`;
    const timeline = document.getElementById('timeline');
    timeline.innerHTML = `<div style="color: #8b949e;">Loading trace data...</div>`;

    try {
        const tenantId = document.getElementById('tenantInput').value || 'default';
        const response = await fetch(`/api/trace/${requestId}`, {
            headers: { 'X-Tenant-ID': tenantId }
        });
        const data = await response.json();
        if (response.ok) {
            renderTimeline(data.timeline);
        } else {
            timeline.innerHTML = `<div style="color: #ff7b72;">${escapeHtml(data.detail || 'Failed to load')}</div>`;
        }
    } catch (error) {
        console.error("Error fetching trace:", error);
        timeline.innerHTML = `<div style="color: #ff7b72;">Failed to load trace details.</div>`;
    }
}

function renderTimeline(events) {
    const timeline = document.getElementById('timeline');
    timeline.innerHTML = '';

    if (!events || events.length === 0) {
        timeline.innerHTML = `<div style="color: #8b949e;">No events found for this request.</div>`;
        return;
    }

    events.forEach(event => {
        const card = document.createElement('div');
        card.className = 'timeline-card';
        
        let typeClass = '';
        if (event.type === 'command') typeClass = 'type-command';
        if (event.type === 'token_usage') typeClass = 'type-token';
        if (typeClass) {
            card.classList.add(typeClass);
        }

        const date = new Date(event.created_at).toLocaleTimeString();
        
        let bodyHtml = '';
        
        if (event.type === 'turn') {
            bodyHtml = `<pre>${escapeHtml(event.content)}</pre>`;
        } else if (event.type === 'command') {
            bodyHtml = `
                <div class="command-tag">${escapeHtml(event.command)}</div>
                <div style="margin-bottom: 10px;"><strong>Reasoning:</strong> ${escapeHtml(event.reasoning)}</div>
                <div style="display: flex; gap: 10px; margin-bottom: 10px;">
                    <span style="color: ${event.exit_code === 0 ? '#3fb950' : '#f85149'}">Exit: ${event.exit_code}</span>
                    <span style="color: #8b949e">By: ${event.validated_by}</span>
                </div>
                ${event.stdout ? `<div style="color: #8b949e; font-size: 12px;">STDOUT</div><pre>${escapeHtml(event.stdout)}</pre>` : ''}
                ${event.stderr ? `<div style="color: #ff7b72; font-size: 12px;">STDERR</div><pre style="border-color: #ff7b7233;">${escapeHtml(event.stderr)}</pre>` : ''}
            `;
        } else if (event.type === 'token_usage') {
            bodyHtml = `
                <div style="display: flex; gap: 20px; color: #8b949e;">
                    <div>Model: <span style="color: #c9d1d9">${event.model_name}</span></div>
                    <div>Prompt: <span style="color: #c9d1d9">${event.prompt_tokens}</span></div>
                    <div>Completion: <span style="color: #c9d1d9">${event.completion_tokens}</span></div>
                    <div>Total: <span style="font-weight: bold; color: #d29922">${event.total_tokens}</span></div>
                </div>
            `;
        }

        card.innerHTML = `
            <div class="card-header">
                <span class="agent-badge ${event.agent}">${event.agent.toUpperCase()}</span>
                <span>${date}</span>
            </div>
            <div class="card-body">
                ${bodyHtml}
            </div>
        `;
        
        timeline.appendChild(card);
    });
}

function escapeHtml(unsafe) {
    if (!unsafe) return '';
    return unsafe
         .replace(/&/g, "&amp;")
         .replace(/</g, "&lt;")
         .replace(/>/g, "&gt;")
         .replace(/"/g, "&quot;")
         .replace(/'/g, "&#039;");
}
