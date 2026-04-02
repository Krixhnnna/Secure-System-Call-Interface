#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <time.h>
#define MAX_STR 32
#define MAX_USERS 10
#define LOG_FILE "system_calls.log"
#define MAX_LOG_SIZE 50000

typedef enum { ROLE_USER, ROLE_ADMIN, ROLE_GUEST } Role;

void hash_password(const char *str, char *output) {
    unsigned long hash = 5381;
    int c;
    while ((c = *str++)) {
        hash = ((hash << 5) + hash) + c;
    }
    snprintf(output, MAX_STR, "%lx", hash);
}

bool is_valid_filename(const char* fn) {
    if (strchr(fn, '/') != NULL || strchr(fn, '\\') != NULL || strstr(fn, "..") != NULL) {
        return false;
    }
    return true;
}

typedef struct {
    char user[MAX_STR];
    char pass[MAX_STR];
    Role role;
    bool approved;
    bool locked;
    int fails;
    bool perm_read;
    bool perm_write;
    bool perm_delete;
} User;

User users[MAX_USERS];
int user_count = 0;


void log_activity(User* u, const char* call, int status, const char* msg) {
    time_t now = time(NULL); char* date = ctime(&now); date[strlen(date)-1] = '\0';
    FILE *f = fopen(LOG_FILE, "a");
    if (f) {
        fseek(f, 0, SEEK_END);
        long size = ftell(f);
        if (size > MAX_LOG_SIZE) {
            fclose(f);
            f = fopen(LOG_FILE, "w"); 
        }
        if (f) {
            fprintf(f, "[%s] User: %s | Role: %d | Syscall: %s | Status: %s | Details: %s\n",
                date, u ? u->user : "UNKNOWN", u ? u->role : -1, call, status ? "ALLOWED" : "DENIED", msg);
            fclose(f);
        }
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

bool register_user(const char* u, const char* p, Role r) {
    if (user_count >= MAX_USERS) return false;
    for (int i=0; i<user_count; i++) if (!strcmp(users[i].user, u)) return false;
    
    bool p_write = (r == ROLE_ADMIN);
    bool p_delete = (r == ROLE_ADMIN);
    User new_usr = { .role=r, .approved=false, .locked=false, .fails=0,
                     .perm_read=true, .perm_write=p_write, .perm_delete=p_delete };
    strncpy(new_usr.user, u, MAX_STR);
    new_usr.user[MAX_STR - 1] = '\0';
    
    char hashed_pass[MAX_STR];
    hash_password(p, hashed_pass);
    strncpy(new_usr.pass, hashed_pass, MAX_STR);
    new_usr.pass[MAX_STR - 1] = '\0';
    
    users[user_count++] = new_usr;
    return true;
}

User* login_user(const char* u, const char* p) {
    for (int i=0; i<user_count; i++) {
        if (!strcmp(users[i].user, u)) {
            if (users[i].locked) { printf("Account LOCKED.\n"); return NULL; }
            if (!users[i].approved) { printf("Pending approval.\n"); return NULL; }
            
            char hashed_input[MAX_STR];
            hash_password(p, hashed_input);
            if (!strcmp(users[i].pass, hashed_input)) { users[i].fails = 0; return &users[i]; }
            
            if (++users[i].fails >= 3) users[i].locked = true;
            printf("Wrong password.\n"); return NULL;
        }
    }
    printf("User not found.\n"); return NULL;
}

int check_access(User* u, const char* call) {
    if (!u->approved || u->locked) { 
        log_activity(u, call, 0, "Security Check Failed"); return 0; 
    }
    if (!strcmp(call, "READ") && !u->perm_read) {
        log_activity(u, call, 0, "Permission Denied - No READ Access");
        printf("[ACCESS DENIED] You lack READ permissions.\n");
        return 0;
    }
    if (!strcmp(call, "WRITE") && !u->perm_write) {
        log_activity(u, call, 0, "Permission Denied - No WRITE Access");
        printf("[ACCESS DENIED] You lack WRITE permissions.\n");
        return 0;
    }
    if (!strcmp(call, "DELETE") && !u->perm_delete) {
        log_activity(u, call, 0, "Permission Denied - No DELETE Access");
        printf("[ACCESS DENIED] You lack DELETE permissions.\n");
        return 0;
    }
    return 1;
}

void secure_read(User* u, const char* fn) {
    if (!check_access(u, "READ")) return;
    if (!is_valid_filename(fn)) { log_activity(u, "READ", 0, "Invalid filename block"); printf("[ERROR] Path traversal blocked.\n"); return; }
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
    if (!check_access(u, "WRITE")) return;
    if (!is_valid_filename(fn)) { log_activity(u, "WRITE", 0, "Invalid filename block"); printf("[ERROR] Path traversal blocked.\n"); return; }
    FILE *f = fopen(fn, "w");
    if (!f) { log_activity(u, "WRITE", 0, "File open error"); return; }
    
    fputs(content, f); 
    fclose(f);
    log_activity(u, "WRITE", 1, fn);
    printf("[SUCCESS] Securely written to '%s'.\n", fn);
}

void secure_delete(User* u, const char* fn) {
    if (!check_access(u, "DELETE")) return;
    if (!is_valid_filename(fn)) { log_activity(u, "DELETE", 0, "Invalid filename block"); printf("[ERROR] Path traversal blocked.\n"); return; }
    if (remove(fn) == 0) {
        log_activity(u, "DELETE", 1, fn);
        printf("[SUCCESS] File '%s' permanently deleted.\n", fn);
    } else {
        log_activity(u, "DELETE", 0, "Unlink failed"); 
        perror("[ERROR]");
    }
}


void admin_manage() {
    int c; char target[MAX_STR];
    printf("\n--- Admin Management ---\n1. List Users\n2. Approve\n3. Unlock\n4. Manage Permissions\nChoice: ");
    if (scanf("%d", &c) != 1) { while(getchar()!='\n'); return; }
    while(getchar()!='\n');
    
    if (c==1) {
        for(int i=0; i<user_count; i++) 
            printf("%-10s | Appr: %d | Lock: %d | Perms: [R:%d W:%d D:%d]\n", 
                   users[i].user, users[i].approved, users[i].locked,
                   users[i].perm_read, users[i].perm_write, users[i].perm_delete);
    } else if (c==2 || c==3) {
        printf("Target Username: "); fgets(target, sizeof(target), stdin); target[strcspn(target,"\n")]=0;
        for(int i=0; i<user_count; i++) {
            if (!strcmp(users[i].user, target)) {
                if (c==2) users[i].approved = true;
                if (c==3) { users[i].locked = false; users[i].fails = 0; }
                printf((c==2) ? "User Approved.\n" : "User Unlocked.\n");
            }
        }
    } else if (c==4) {
        printf("Target Username: "); fgets(target, sizeof(target), stdin); target[strcspn(target,"\n")]=0;
        for(int i=0; i<user_count; i++) {
            if (!strcmp(users[i].user, target)) {
                char ans[10];
                printf("Grant READ permission? (y/n): "); fgets(ans, sizeof(ans), stdin);
                users[i].perm_read = (ans[0] == 'y' || ans[0] == 'Y');
                
                printf("Grant WRITE permission? (y/n): "); fgets(ans, sizeof(ans), stdin);
                users[i].perm_write = (ans[0] == 'y' || ans[0] == 'Y');
                
                printf("Grant DELETE permission? (y/n): "); fgets(ans, sizeof(ans), stdin);
                users[i].perm_delete = (ans[0] == 'y' || ans[0] == 'Y');
                
                printf("Permissions updated successfully.\n");
                break;
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
            case 6: 
                if (u->role == ROLE_ADMIN) {
                    admin_manage();
                } else {
                    log_activity(u, "ADMIN_MANAGE", 0, "Attempted unauthorized menu access");
                    printf("[ACCESS DENIED] Unauthorized Menu Option.\n");
                }
                break;
            case 5: case 7: return;
            default: printf("Invalid choice.\n");
        }
    }
}

int main() {

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