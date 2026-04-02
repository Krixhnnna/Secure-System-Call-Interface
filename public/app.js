let currentUser = null;
let currentPass = null;
let isRegisterMode = false;

function toggleAuthMode() {
    isRegisterMode = !isRegisterMode;
    document.getElementById('auth-subtitle').innerText = isRegisterMode ? 'Create a new account' : 'Enter your credentials';
    document.getElementById('auth-btn').innerText = isRegisterMode ? 'Register Account' : 'Authenticate Session';
    document.getElementById('toggle-lbl').innerText = isRegisterMode ? 'Already have an account?' : "Don't have an account?";
    document.getElementById('toggle-link').innerText = isRegisterMode ? 'Login' : 'Register';
    document.getElementById('auth-msg').innerText = '';
    document.getElementById('auth-msg').className = 'msg';
}

async function handleAuth() {
    const u = document.getElementById('username').value.trim();
    const p = document.getElementById('password').value.trim();
    const msg = document.getElementById('auth-msg');
    
    if (!u || !p) { msg.className='msg error'; msg.innerText='Please enter both username and password.'; return; }
    
    if (isRegisterMode) {
        const res = await fetch('/api/register', {
            method: 'POST', headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({username: u, password: p})
        });
        const data = await res.json();
        
        if (data.success) {
            msg.className = 'msg success'; 
            msg.innerText = 'Registration successful! Pending admin approval.';
            setTimeout(() => { toggleAuthMode(); document.getElementById('password').value=''; }, 2000);
        } else {
            msg.className = 'msg error'; msg.innerText = 'Registration failed. Max users reached or username taken.';
        }
        return;
    }

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
        if (data.role === 1) {
            document.getElementById('admin-panel').style.display = 'block';
            fetchUsersList();
        }
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
    document.getElementById('admin-panel').style.display = 'none';
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
    fetchLogs(); 
}

async function fetchLogs() {
    if (!currentUser) return; 
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


document.getElementById('password').addEventListener('keypress', function (e) {
    if (e.key === 'Enter') handleAuth();
});

async function fetchUsersList() {
    if (!currentUser) return;
    try {
        const res = await fetch('/api/users', {
            method: 'POST', headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({username: currentUser, password: currentPass})
        });
        const data = await res.json();
        if (data.success) {
            renderUsersTable(data.users);
        }
    } catch(e) {
        console.error("Failed to fetch users", e);
    }
}

function renderUsersTable(users) {
    const tbody = document.getElementById('users-tbody');
    tbody.innerHTML = '';
    
    let pendingCount = 0;

    users.forEach(u => {
        const tr = document.createElement('tr');
        
        const status = [];
        if (u.is_locked) status.push('<span class="badge error">Locked</span>');
        if (!u.is_approved) {
            status.push('<span class="badge warning">Pending</span>');
            pendingCount++;
        }
        if (status.length === 0) status.push('<span class="badge success">Active</span>');

        let actionsHtml = '';
        if (u.role !== 1) { 
            let extraBtns = '';
            if (!u.is_approved) extraBtns += `<button class="outline-btn" style="padding: 0.3rem 0.6rem; font-size: 0.8rem; color: #10B981; border-color: rgba(16, 185, 129, 0.4);" onclick="manageUserState('approve', '${u.username}')">Approve</button>`;
            if (u.is_locked) extraBtns += `<button class="outline-btn" style="padding: 0.3rem 0.6rem; font-size: 0.8rem; color: #FCD34D; border-color: rgba(252, 211, 77, 0.4);" onclick="manageUserState('unlock', '${u.username}')">Unlock</button>`;

            actionsHtml = `
            <div style="display:flex; gap:0.5rem; flex-wrap:wrap;">
                ${extraBtns}
                <button class="outline-btn" style="padding: 0.3rem 0.6rem; font-size: 0.8rem;" onclick="updateUserPermissions('${u.username}')">Save</button>
            </div>`;
        } else {
            actionsHtml = '<span style="font-size:0.8rem;color:#71717A;">System Admin</span>';
        }

        tr.innerHTML = `
            <td>${u.username} <span class="badge">${u.role === 1 ? 'ADMIN' : 'USER'}</span></td>
            <td>${status.join(' ')}</td>
            <td><input type="checkbox" id="r_${u.username}" ${u.perm_read ? 'checked' : ''} ${u.role === 1 ? 'disabled' : ''}></td>
            <td><input type="checkbox" id="w_${u.username}" ${u.perm_write ? 'checked' : ''} ${u.role === 1 ? 'disabled' : ''}></td>
            <td><input type="checkbox" id="d_${u.username}" ${u.perm_delete ? 'checked' : ''} ${u.role === 1 ? 'disabled' : ''}></td>
            <td>${actionsHtml}</td>
        `;
        tbody.appendChild(tr);
    });

    const badge = document.getElementById('pending-badge');
    if (pendingCount > 0) {
        badge.style.display = 'inline-block';
        badge.innerText = `${pendingCount} Pending`;
    } else {
        badge.style.display = 'none';
    }
}

async function manageUserState(action, targetUser) {
    try {
        const res = await fetch(`/api/${action}`, {
            method: 'POST', headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({
                username: currentUser, password: currentPass, target_user: targetUser
            })
        });
        const data = await res.json();
        if (data.success) {
            fetchUsersList();
            fetchLogs();
            const msg = document.getElementById('status-msg');
            msg.className = 'msg success'; msg.innerText = `Successfully performed ${action} on ${targetUser}.`;
        } else {
            const msg = document.getElementById('status-msg');
            msg.className = 'msg error'; msg.innerText = data.error || `Failed to ${action} user.`;
        }
    } catch(e) {
        alert(`Error executing ${action}`);
    }
}

async function updateUserPermissions(targetUser) {
    const perm_read = document.getElementById(`r_${targetUser}`).checked;
    const perm_write = document.getElementById(`w_${targetUser}`).checked;
    const perm_delete = document.getElementById(`d_${targetUser}`).checked;
    
    try {
        const res = await fetch('/api/permissions', {
            method: 'POST', headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({
                username: currentUser, password: currentPass,
                target_user: targetUser,
                perm_read, perm_write, perm_delete
            })
        });
        const data = await res.json();
        if (data.success) {
            fetchUsersList();
            fetchLogs();
            const msg = document.getElementById('status-msg');
            msg.className = 'msg success'; msg.innerText = `Updated permissions for ${targetUser}.`;
        } else {
            const msg = document.getElementById('status-msg');
            msg.className = 'msg error'; msg.innerText = data.error || 'Failed to update permissions';
        }
    } catch(e) {
        alert('Error updating permissions');
    }
}
