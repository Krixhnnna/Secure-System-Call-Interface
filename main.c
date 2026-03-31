#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <time.h>

#define MAX_STR 32
#define MAX_USERS 10
#define LOG_FILE "system_calls.log"

typedef enum { ROLE_USER, ROLE_ADMIN, ROLE_GUEST } Role;

typedef struct {
    char user[MAX_STR];
    char pass[MAX_STR];
    Role role;
    bool approved;
    bool locked;
    int fails;
} User;

User users[MAX_USERS];
int user_count = 0;

/* ================== LOGGER ================== */
void log_activity(User* u, const char* call, int status, const char* msg) {
    time_t now = time(NULL); char* date = ctime(&now); date[strlen(date)-1] = '\0';
    FILE *f = fopen(LOG_FILE, "a");
    if (f) {
        fprintf(f, "[%s] User: %s | Role: %d | Syscall: %s | Status: %s | Details: %s\n",
            date, u ? u->user : "UNKNOWN", u ? u->role : -1, call, status ? "ALLOWED" : "DENIED", msg);
        fclose(f);
    }
}

void view_logs() {
    FILE *f = fopen(LOG_FILE, "r");
    if (!f) { printf("No logs found.\n"); return; }
    char buf[1024];
    printf("\n=== SYSTEM AUDIT LOGS ===\n");
    while (fgets(buf, sizeof(buf), f)) printf("%s", buf);
    printf("=========================\n");
    fclose(f);
}

/* ================== AUTH ================== */
bool register_user(const char* u, const char* p, Role r) {
    if (user_count >= MAX_USERS) return false;
    for (int i=0; i<user_count; i++) if (!strcmp(users[i].user, u)) return false;
    
    User new_usr = { .role=r, .approved=false, .locked=false, .fails=0 };
    strncpy(new_usr.user, u, MAX_STR);
    strncpy(new_usr.pass, p, MAX_STR);
    users[user_count++] = new_usr;
    return true;
}

User* login_user(const char* u, const char* p) {
    for (int i=0; i<user_count; i++) {
        if (!strcmp(users[i].user, u)) {
            if (users[i].locked) { printf("Account LOCKED.\n"); return NULL; }
            if (!users[i].approved) { printf("Pending approval.\n"); return NULL; }
            if (!strcmp(users[i].pass, p)) { users[i].fails = 0; return &users[i]; }
            
            if (++users[i].fails >= 3) users[i].locked = true;
            printf("Wrong password.\n"); return NULL;
        }
    }
    printf("User not found.\n"); return NULL;
}

/* ================== SECURE OS SYSCALLS ================== */
int check_access(User* u, Role req_role, const char* call) {
    if (!u->approved || u->locked) { 
        log_activity(u, call, 0, "Security Check Failed"); return 0; 
    }
    if (req_role == ROLE_ADMIN && u->role != ROLE_ADMIN) {
        log_activity(u, call, 0, "RBAC Limit - Requires ADMIN");
        printf("[ACCESS DENIED] Insufficient Permissions.\n");
        return 0;
    }
    return 1;
}

void secure_read(User* u, const char* fn) {
    if (!check_access(u, ROLE_USER, "READ")) return;
    FILE *f = fopen(fn, "r");
    if (!f) { log_activity(u, "READ", 0, "File open error"); perror("[ERROR]"); return; }
    
    log_activity(u, "READ", 1, fn);
    printf("[SUCCESS] Reading '%s':\n----------------\n", fn);
    char buf[1024]; 
    while (fgets(buf, sizeof(buf), f)) printf("%s", buf);
    printf("\n----------------\n"); 
    fclose(f);
}

void secure_write(User* u, const char* fn, const char* content) {
    if (!check_access(u, ROLE_USER, "WRITE")) return;
    FILE *f = fopen(fn, "w");
    if (!f) { log_activity(u, "WRITE", 0, "File open error"); return; }
    
    fputs(content, f); 
    fclose(f);
    log_activity(u, "WRITE", 1, fn);
    printf("[SUCCESS] Securely written to '%s'.\n", fn);
}

void secure_delete(User* u, const char* fn) {
    if (!check_access(u, ROLE_ADMIN, "DELETE")) return;
    if (remove(fn) == 0) {
        log_activity(u, "DELETE", 1, fn);
        printf("[SUCCESS] File '%s' permanently deleted.\n", fn);
    } else {
        log_activity(u, "DELETE", 0, "Unlink failed"); 
        perror("[ERROR]");
    }
}

/* ================== MENUS ================== */
void admin_manage() {
    int c; char target[MAX_STR];
    printf("\n--- Admin Management ---\n1. List Users\n2. Approve\n3. Unlock\nChoice: ");
    if (scanf("%d", &c) != 1) { while(getchar()!='\n'); return; }
    while(getchar()!='\n');
    
    if (c==1) {
        for(int i=0; i<user_count; i++) 
            printf("%-10s | Role: %d | Appr: %d | Lock: %d\n", users[i].user, users[i].role, users[i].approved, users[i].locked);
    } else if (c==2 || c==3) {
        printf("Target Username: "); fgets(target, sizeof(target), stdin); target[strcspn(target,"\n")]=0;
        for(int i=0; i<user_count; i++) {
            if (!strcmp(users[i].user, target)) {
                if (c==2) users[i].approved = true;
                if (c==3) { users[i].locked = false; users[i].fails = 0; }
                printf((c==2) ? "User Approved.\n" : "User Unlocked.\n");
            }
        }
    }
}

void authenticated_menu(User* u) {
    int c; char f[128], content[512];
    while (1) {
        printf("\n--- User: %s ---\n1. Read File\n2. Write File\n3. Delete File\n4. View Logs\n", u->user);
        if (u->role == ROLE_ADMIN) printf("6. [ADMIN] Manage\n");
        printf("7. Logout\nChoice: ");
        if (scanf("%d", &c) != 1) { while(getchar()!='\n'); continue; }
        while(getchar()!='\n');
        
        switch(c) {
            case 1: printf("Filename: "); fgets(f, sizeof(f), stdin); f[strcspn(f,"\n")]=0; secure_read(u, f); break;
            case 2: printf("Filename: "); fgets(f, sizeof(f), stdin); f[strcspn(f,"\n")]=0;
                    printf("Content: "); fgets(content, sizeof(content), stdin); content[strcspn(content,"\n")]=0;
                    secure_write(u, f, content); break;
            case 3: printf("Filename: "); fgets(f, sizeof(f), stdin); f[strcspn(f,"\n")]=0; secure_delete(u, f); break;
            case 4: view_logs(); break;
            case 6: if (u->role == ROLE_ADMIN) admin_manage(); break;
            case 5: case 7: return;
            default: printf("Invalid choice.\n");
        }
    }
}

int main() {
    // Initialize default accounts
    register_user("admin", "admin123", ROLE_ADMIN); users[0].approved = true;
    register_user("user", "user123", ROLE_USER); users[1].approved = true;
    
    int c; char u[MAX_STR], p[MAX_STR];
    while(1) {
        printf("\n==========================================\n");
        printf("   SECURE SYSTEM CALL INTERFACE (SIM)     \n");
        printf("==========================================\n");
        printf("1. Login\n2. Register\n3. Exit\nChoice: ");
        
        if (scanf("%d", &c) != 1) { while(getchar()!='\n'); continue; }
        while(getchar()!='\n');
        
        if (c==1) {
            printf("Username: "); fgets(u, sizeof(u), stdin); u[strcspn(u,"\n")]=0;
            printf("Password: "); fgets(p, sizeof(p), stdin); p[strcspn(p,"\n")]=0;
            User* usr = login_user(u, p);
            if (usr) { 
                log_activity(usr, "LOGIN", 1, "Successful"); 
                printf("Login successful!\n");
                authenticated_menu(usr); 
            } else {
                log_activity(NULL, "LOGIN", 0, "Failed attempt");
            }
        } 
        else if (c==2) {
            printf("New Username: "); fgets(u, sizeof(u), stdin); u[strcspn(u,"\n")]=0;
            printf("New Password: "); fgets(p, sizeof(p), stdin); p[strcspn(p,"\n")]=0;
            if (register_user(u, p, ROLE_USER)) printf("Registration successful! Pending admin approval.\n");
            else printf("Registration failed.\n");
        } 
        else if (c==3) break;
    }
    return 0;
}