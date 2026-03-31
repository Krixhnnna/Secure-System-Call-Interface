const express = require('express');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = 8000;
const LOG_FILE = 'system_calls.log';

// Middleware
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// --- Memory State (Simulating C memory) ---
const ROLE_USER = 0, ROLE_ADMIN = 1, ROLE_GUEST = 2;

let users = [
    { username: 'admin', password: 'admin123', role: ROLE_ADMIN, is_approved: true, is_locked: false, failed_attempts: 0 },
    { username: 'user', password: 'user123', role: ROLE_USER, is_approved: true, is_locked: false, failed_attempts: 0 }
];

// --- Audit Logger ---
function log_activity(username, role, syscallName, status, details) {
    const dateStr = new Date().toString().replace(/ \([^)]*\)$/, '');
    const userRoleStr = role !== undefined ? role : -1;
    const statusStr = status ? "ALLOWED" : "DENIED";
    
    // Matched exact C format: [%s] User: %s | Role: %d | Syscall: %s | Status: %s | Details: %s\n
    const entry = `[${dateStr}] User: ${username || "UNKNOWN"} | Role: ${userRoleStr} | Syscall: ${syscallName} | Status: ${statusStr} | Details: ${details}\n`;
    
    fs.appendFileSync(LOG_FILE, entry);
}

// --- Auth Helper ---
function authenticate(username, password) {
    const user = users.find(u => u.username === username);
    if (!user) return { error: "User not found", code: 1, user: null };
    if (user.is_locked) return { error: "Account Locked (too many attempts)", code: 3, user: null };
    if (!user.is_approved) return { error: "Account Pending Approval", code: 4, user: null };
    
    if (user.password === password) {
        user.failed_attempts = 0; // Reset
        return { success: true, user };
    } else {
        user.failed_attempts++;
        if (user.failed_attempts >= 3) {
            user.is_locked = true;
            return { error: "Account Locked (too many attempts)", code: 3, user: null };
        }
        return { error: "Invalid credentials", code: 2, user: null };
    }
}

// --- API Endpoints ---

// Login
app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    const auth = authenticate(username, password);
    
    if (auth.success) {
        log_activity(username, auth.user.role, "LOGIN(API)", 1, "User logged in via Web UI");
        res.json({ success: true, role: auth.user.role, is_approved: auth.user.is_approved });
    } else {
        log_activity(username, undefined, "LOGIN(API)", 0, auth.error);
        res.json({ success: false, error: auth.error });
    }
});

// Register
app.post('/api/register', (req, res) => {
    const { username, password, role } = req.body;
    
    if (users.length >= 10) return res.json({ success: false }); // MAX_USERS limit
    if (users.find(u => u.username === username)) return res.json({ success: false }); // Taken
    
    users.push({
        username, 
        password, 
        role: role || ROLE_USER, 
        is_approved: false, 
        is_locked: false, 
        failed_attempts: 0
    });
    
    res.json({ success: true });
});

// Read Call
app.post('/api/read', (req, res) => {
    const { username, password, filename } = req.body;
    const auth = authenticate(username, password);
    
    if (!auth.success) return res.json({ success: false, status: "Authentication Failed" });
    
    const user = auth.user;
    if (user.role !== ROLE_ADMIN && user.role !== ROLE_USER) {
        log_activity(user.username, user.role, "READ", 0, "RBAC Limit - Role not allowed");
        return res.json({ success: false, status: "Access Denied: Insufficient Permissions" });
    }

    try {
        const content = fs.readFileSync(filename, 'utf-8');
        log_activity(user.username, user.role, "READ", 1, filename);
        res.json({ success: true, status: "Success", content });
    } catch (e) {
        const errorMsg = `Failed to open file: ${e.message}`;
        log_activity(user.username, user.role, "READ", 0, errorMsg);
        res.json({ success: false, status: "File not found or unreadable" });
    }
});

// Write Call
app.post('/api/write', (req, res) => {
    const { username, password, filename, content } = req.body;
    const auth = authenticate(username, password);
    
    if (!auth.success) return res.json({ success: false, status: "Authentication Failed" });
    
    const user = auth.user;
    if (user.role !== ROLE_ADMIN && user.role !== ROLE_USER) {
        log_activity(user.username, user.role, "WRITE", 0, "RBAC Limit");
        return res.json({ success: false, status: "Access Denied: Insufficient Permissions" });
    }

    try {
        fs.writeFileSync(filename, content);
        log_activity(user.username, user.role, "WRITE", 1, filename);
        res.json({ success: true, status: "Success" });
    } catch (e) {
        log_activity(user.username, user.role, "WRITE", 0, "Write IO Error");
        res.json({ success: false, status: "Write Error" });
    }
});

// Delete Call
app.post('/api/delete', (req, res) => {
    const { username, password, filename } = req.body;
    const auth = authenticate(username, password);
    
    if (!auth.success) return res.json({ success: false, status: "Authentication Failed" });
    
    const user = auth.user;
    if (user.role !== ROLE_ADMIN) {
        log_activity(user.username, user.role, "DELETE", 0, "RBAC Limit - Requires ADMIN");
        return res.json({ success: false, status: "Access Denied: Only ADMIN can delete" });
    }

    try {
        fs.unlinkSync(filename);
        log_activity(user.username, user.role, "DELETE", 1, filename);
        res.json({ success: true, status: "Success" });
    } catch (e) {
        log_activity(user.username, user.role, "DELETE", 0, "Unlink failed");
        res.json({ success: false, status: "Delete Error" });
    }
});

// Logs Endpoint
app.get('/api/logs', (req, res) => {
    try {
        const logs = fs.readFileSync(LOG_FILE, 'utf-8');
        res.json({ logs: logs || "Log file empty." });
    } catch (e) {
        res.json({ logs: "Log file unreadable or missing." });
    }
});

// Admin: Approve
app.post('/api/approve', (req, res) => {
    const { username, password, target_user } = req.body;
    const auth = authenticate(username, password);
    if (!auth.success || auth.user.role !== ROLE_ADMIN) return res.json({ success: false, error: "Requires Admin" });
    
    let target = users.find(u => u.username === target_user);
    if (target) {
        target.is_approved = true;
        log_activity(username, auth.user.role, "APPROVE", 1, `Approved ${target_user}`);
        res.json({ success: true });
    } else {
        res.json({ success: false, error: "Target not found" });
    }
});

// Admin: Unlock
app.post('/api/unlock', (req, res) => {
    const { username, password, target_user } = req.body;
    const auth = authenticate(username, password);
    if (!auth.success || auth.user.role !== ROLE_ADMIN) return res.json({ success: false, error: "Requires Admin" });
    
    let target = users.find(u => u.username === target_user);
    if (target) {
        target.is_locked = false;
        target.failed_attempts = 0;
        log_activity(username, auth.user.role, "UNLOCK", 1, `Unlocked ${target_user}`);
        res.json({ success: true });
    } else {
        res.json({ success: false, error: "Target not found" });
    }
});

// Start Server
app.listen(PORT, () => {
    console.log(`Node.js Secure Backend natively running on http://localhost:${PORT}`);
});
