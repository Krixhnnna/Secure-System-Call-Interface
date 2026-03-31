let currentUser = null;
let currentPass = null;

async function handleAuth() {
    const u = document.getElementById('username').value.trim();
    const p = document.getElementById('password').value.trim();
    const msg = document.getElementById('auth-msg');
    
    if (!u || !p) { msg.className='msg error'; msg.innerText='Please enter both username and password.'; return; }
    
    const res = await fetch('/api/login', {
        method: 'POST', headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({username: u, password: p})
    });
    const data = await res.json();
    
    if (data.success) {
        currentUser = u; currentPass = p;
        document.getElementById('auth-screen').classList.remove('active');
        document.getElementById('main-screen').classList.add('active');
        document.getElementById('user-badge').innerText = `Role: ${data.role === 1 ? 'ADMIN' : 'USER'}`;
        fetchLogs();
        msg.innerText = '';
    } else {
        msg.className = 'msg error'; msg.innerText = data.error || 'Login failed';
    }
}

function logout() {
    currentUser = null; currentPass = null;
    document.getElementById('main-screen').classList.remove('active');
    document.getElementById('auth-screen').classList.add('active');
    document.getElementById('username').value = '';
    document.getElementById('password').value = '';
    document.getElementById('auth-msg').innerText = '';
    document.getElementById('status-msg').innerText = '';
}

async function syscall(action) {
    const filename = document.getElementById('filename').value.trim();
    const content = document.getElementById('file-content').value;
    const msg = document.getElementById('status-msg');
    
    if (!filename) { msg.className='msg error'; msg.innerText='Filename required.'; return; }
    
    let path = `/api/${action}`;
    const res = await fetch(path, {
        method: 'POST', headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({username: currentUser, password: currentPass, filename, content})
    });
    
    const data = await res.json();
    if (data.success) {
        msg.className = 'msg success'; 
        msg.innerText = data.status || 'Operation successful';
        if (action === 'read' && data.content !== undefined) {
             document.getElementById('file-content').value = data.content;
        }
    } else {
        msg.className = 'msg error'; msg.innerText = data.status || data.error || 'Operation failed';
    }
    fetchLogs(); // Refresh logs after syscall
}

async function fetchLogs() {
    if (!currentUser) return; // don't fetch if logged out
    const logBox = document.getElementById('log-output');
    try {
        const res = await fetch('/api/logs');
        const data = await res.json();
        logBox.innerText = data.logs;
        logBox.scrollTop = logBox.scrollHeight;
    } catch(e) {
        logBox.innerText = 'Failed to fetch logs.';
    }
}

// Add enter key support for login
document.getElementById('password').addEventListener('keypress', function (e) {
    if (e.key === 'Enter') handleAuth();
});
