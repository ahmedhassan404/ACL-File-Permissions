#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#define READ 4
#define WRITE 2
#define EXECUTE 1

#define USER_OWNER 0
#define GROUP_OWNER 1
#define OTHER 2
#define NAMED_USER 3
#define NAMED_GROUP 4
#define MASK 5

#define FILE_OWNER_UID 1000
#define FILE_OWNER_GID 2000

typedef struct {
    int type;
    int id;
    int permissions;
} ACLEntry;

typedef struct {
    ACLEntry *entries;
    int count;
} ACL;

void initializeDefaultACL(ACL *acl);
bool hasPermission(ACL *acl, int eUID, int eGID, int requestedPermission);
void displayACLEntries(ACL *acl);
int parsePermissionString(const char *permStr);
void freeACL(ACL *acl);
void readACLFromFile(ACL *acl, const char *filename);

int main() {
    ACL acl;

    char choice;
    printf("Do you want to load ACL from file? (y/n): ");
    scanf(" %c", &choice);

    if (choice == 'y' || choice == 'Y') {
        readACLFromFile(&acl, "acl.txt");
    } else {
        initializeDefaultACL(&acl);
    }

    printf("\nACL Entries:\n");
    displayACLEntries(&acl);

    int eUID, eGID, requestedPermission;
    char permStr[10];

    printf("\nEnter effective UID (eUID): ");
    scanf("%d", &eUID);
    printf("Enter effective GID (eGID): ");
    scanf("%d", &eGID);
    printf("Enter desired permission (r, w, x, rw, rx, wx, rwx): ");
    scanf("%s", permStr);

    requestedPermission = 0;
    if (strchr(permStr, 'r') != NULL) requestedPermission |= READ;
    if (strchr(permStr, 'w') != NULL) requestedPermission |= WRITE;
    if (strchr(permStr, 'x') != NULL) requestedPermission |= EXECUTE;

    if (hasPermission(&acl, eUID, eGID, requestedPermission)) {
        printf("\nAccess GRANTED!\n");
    } else {
        printf("\nAccess DENIED!\n");
    }

    freeACL(&acl);
    return 0;
}

void initializeDefaultACL(ACL *acl) {
    acl->entries = (ACLEntry *)malloc(8 * sizeof(ACLEntry));
    acl->count = 8;

    acl->entries[0] = (ACLEntry){USER_OWNER, -1, READ | WRITE};
    acl->entries[1] = (ACLEntry){NAMED_USER, 1001, READ | WRITE};
    acl->entries[2] = (ACLEntry){NAMED_USER, 1002, READ};
    acl->entries[3] = (ACLEntry){GROUP_OWNER, -1, READ | WRITE};
    acl->entries[4] = (ACLEntry){NAMED_GROUP, 2001, READ};
    acl->entries[5] = (ACLEntry){NAMED_GROUP, 2002, READ};
    acl->entries[6] = (ACLEntry){MASK, -1, READ | WRITE};
    acl->entries[7] = (ACLEntry){OTHER, -1, 0};
}

bool hasPermission(ACL *acl, int eUID, int eGID, int requestedPermission) {
    for (int i = 0; i < acl->count; i++) {
        if (acl->entries[i].type == USER_OWNER && eUID == FILE_OWNER_UID) {
            return (acl->entries[i].permissions & requestedPermission) == requestedPermission;
        }
    }

    for (int i = 0; i < acl->count; i++) {
        if (acl->entries[i].type == NAMED_USER && acl->entries[i].id == eUID) {
            int maskPermissions = 0;
            for (int j = 0; j < acl->count; j++) {
                if (acl->entries[j].type == MASK) {
                    maskPermissions = acl->entries[j].permissions;
                    break;
                }
            }
            int effectivePermissions = acl->entries[i].permissions & maskPermissions;
            return (effectivePermissions & requestedPermission) == requestedPermission;
        }
    }

    bool inGroupOwner = false;
    int groupOwnerPermissions = 0;
    for (int i = 0; i < acl->count; i++) {
        if (acl->entries[i].type == GROUP_OWNER && eGID == FILE_OWNER_GID) {
            inGroupOwner = true;
            groupOwnerPermissions = acl->entries[i].permissions;
            break;
        }
    }

    bool inNamedGroup = false;
    int namedGroupPermissions = 0;
    for (int i = 0; i < acl->count; i++) {
        if (acl->entries[i].type == NAMED_GROUP && acl->entries[i].id == eGID) {
            inNamedGroup = true;
            namedGroupPermissions = acl->entries[i].permissions;
            break;
        }
    }

    int maskPermissions = 0;
    for (int i = 0; i < acl->count; i++) {
        if (acl->entries[i].type == MASK) {
            maskPermissions = acl->entries[i].permissions;
            break;
        }
    }

    if (inGroupOwner) {
        int effectivePermissions = groupOwnerPermissions & maskPermissions;
        if ((effectivePermissions & requestedPermission) == requestedPermission) return true;
    }

    if (inNamedGroup) {
        int effectivePermissions = namedGroupPermissions & maskPermissions;
        if ((effectivePermissions & requestedPermission) == requestedPermission) return true;
    }

    for (int i = 0; i < acl->count; i++) {
        if (acl->entries[i].type == OTHER) {
            return (acl->entries[i].permissions & requestedPermission) == requestedPermission;
        }
    }

    return false;
}

void displayACLEntries(ACL *acl) {
    const char *typeNames[] = {"USER_OWNER", "GROUP_OWNER", "OTHER", "NAMED_USER", "NAMED_GROUP", "MASK"};
    for (int i = 0; i < acl->count; i++) {
        printf("Entry %d: Type=%s, ", i, typeNames[acl->entries[i].type]);
        if (acl->entries[i].id != -1) {
            printf("ID=%d, ", acl->entries[i].id);
        } else {
            printf("ID=N/A, ");
        }
        printf("Permissions=%c%c%c\n",
               (acl->entries[i].permissions & READ) ? 'r' : '-',
               (acl->entries[i].permissions & WRITE) ? 'w' : '-',
               (acl->entries[i].permissions & EXECUTE) ? 'x' : '-');
    }
}

int parsePermissionString(const char *permStr) {
    int permissions = 0;
    if (strlen(permStr) >= 3) {
        if (permStr[0] == 'r') permissions |= READ;
        if (permStr[1] == 'w') permissions |= WRITE;
        if (permStr[2] == 'x') permissions |= EXECUTE;
    }
    return permissions;
}

void freeACL(ACL *acl) {
    if (acl->entries != NULL) {
        free(acl->entries);
        acl->entries = NULL;
        acl->count = 0;
    }
}

void readACLFromFile(ACL *acl, const char *filename) {
    FILE *file = fopen(filename, "r");
    if (file == NULL) {
        printf("Error opening file %s\n", filename);
        return;
    }

    int lineCount = 0;
    char buffer[256];
    while (fgets(buffer, sizeof(buffer), file) != NULL) {
        if (strlen(buffer) > 1) lineCount++;
    }

    rewind(file);

    if (acl->entries != NULL) free(acl->entries);
    acl->entries = (ACLEntry *)malloc(lineCount * sizeof(ACLEntry));
    acl->count = lineCount;

    int entryIndex = 0;
    while (fgets(buffer, sizeof(buffer), file) != NULL) {
        if (strlen(buffer) <= 1) continue;
        buffer[strcspn(buffer, "\n")] = 0;
        char *token = strtok(buffer, ":");
        if (token == NULL) continue;

        if (strcmp(token, "user") == 0) {
            token = strtok(NULL, ":");
            if (token == NULL) continue;
            if (strlen(token) == 0) {
                acl->entries[entryIndex].type = USER_OWNER;
                acl->entries[entryIndex].id = -1;
            } else {
                acl->entries[entryIndex].type = NAMED_USER;
                int uid = 0;
                for (int i = 0; token[i] != '\0'; i++) uid = uid * 31 + token[i];
                acl->entries[entryIndex].id = 1000 + (uid % 100);
            }
        } else if (strcmp(token, "group") == 0) {
            token = strtok(NULL, ":");
            if (token == NULL) continue;
            if (strlen(token) == 0) {
                acl->entries[entryIndex].type = GROUP_OWNER;
                acl->entries[entryIndex].id = -1;
            } else {
                acl->entries[entryIndex].type = NAMED_GROUP;
                int gid = 0;
                for (int i = 0; token[i] != '\0'; i++) gid = gid * 31 + token[i];
                acl->entries[entryIndex].id = 2000 + (gid % 100);
            }
        } else if (strcmp(token, "mask") == 0) {
            acl->entries[entryIndex].type = MASK;
            acl->entries[entryIndex].id = -1;
            token = strtok(NULL, ":");
        } else if (strcmp(token, "other") == 0) {
            acl->entries[entryIndex].type = OTHER;
            acl->entries[entryIndex].id = -1;
            token = strtok(NULL, ":");
        } else {
            continue;
        }

        token = strtok(NULL, ":");
        if (token == NULL) continue;
        acl->entries[entryIndex].permissions = parsePermissionString(token);
        entryIndex++;
    }

    acl->count = entryIndex;
    fclose(file);
}
