#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

#define MAX_LINE_LENGTH 1024
#define MAX_PATTERNS 128

typedef struct {
    char *name;
    char *description;
    char *patterns[MAX_PATTERNS];
    int patternCount;
} MalwareRule;

static char *strdup_safe(const char *src) {
    if (!src) return NULL;
    size_t len = strlen(src) + 1;
    char *dst = (char *)malloc(len);
    if (dst) memcpy(dst, src, len);
    return dst;
}

static void freeRule(MalwareRule *rule) {
    if (!rule) return;
    free(rule->name);
    free(rule->description);
    for (int i = 0; i < rule->patternCount; ++i) {
        free(rule->patterns[i]);
        rule->patterns[i] = NULL;
    }
    rule->patternCount = 0;
}

static char *readFile(const char *path) {
    FILE *file = fopen(path, "rb");
    if (!file) return NULL;

    if (fseek(file, 0, SEEK_END) != 0) {
        fclose(file);
        return NULL;
    }

    long size = ftell(file);
    if (size < 0) {
        fclose(file);
        return NULL;
    }
    rewind(file);

    char *buffer = (char *)malloc((size_t)size + 1);
    if (!buffer) {
        fclose(file);
        return NULL;
    }

    if (fread(buffer, 1, (size_t)size, file) != (size_t)size) {
        free(buffer);
        fclose(file);
        return NULL;
    }
    buffer[size] = '\0';
    fclose(file);
    return buffer;
}

static int hasRuleExtension(const char *filename) {
    const char *dot = strrchr(filename, '.');
    return dot && _stricmp(dot, ".rule") == 0;
}

static int loadRule(const char *path, MalwareRule *rule) {
    FILE *file = fopen(path, "r");
    if (!file) return 0;

    char line[MAX_LINE_LENGTH];
    rule->name = NULL;
    rule->description = NULL;
    rule->patternCount = 0;

    while (fgets(line, sizeof(line), file)) {
        size_t len = strlen(line);
        while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r')) {
            line[--len] = '\0';
        }

        if (strncmp(line, "Name=", 5) == 0) {
            free(rule->name);
            rule->name = strdup_safe(line + 5);
        } else if (strncmp(line, "Description=", 12) == 0) {
            free(rule->description);
            rule->description = strdup_safe(line + 12);
        } else if (strncmp(line, "STRING:", 7) == 0) {
            if (rule->patternCount < MAX_PATTERNS) {
                rule->patterns[rule->patternCount++] = strdup_safe(line + 7);
            }
        }
    }

    fclose(file);
    return rule->patternCount > 0 && rule->name != NULL;
}

static int detectMalware(const char *content, const MalwareRule *rule) {
    if (!content || !rule) return 0;

    for (int i = 0; i < rule->patternCount; ++i) {
        if (!strstr(content, rule->patterns[i])) {
            return 0;
        }
    }
    return 1;
}

static int scanRules(const char *folderPath, const char *content) {
    WIN32_FIND_DATAA findData;
    char searchPath[MAX_PATH];
    HANDLE findHandle;
    int foundCount = 0;

    snprintf(searchPath, sizeof(searchPath), "%s\\*", folderPath);
    findHandle = FindFirstFileA(searchPath, &findData);
    if (findHandle == INVALID_HANDLE_VALUE) return 0;

    do {
        if (strcmp(findData.cFileName, ".") == 0 || strcmp(findData.cFileName, "..") == 0) {
            continue;
        }

        char path[MAX_PATH];
        snprintf(path, sizeof(path), "%s\\%s", folderPath, findData.cFileName);

        if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            foundCount += scanRules(path, content);
            continue;
        }

        if (hasRuleExtension(findData.cFileName)) {
            MalwareRule rule = {0};
            if (loadRule(path, &rule) && detectMalware(content, &rule)) {
                foundCount++;
                printf("========================\n");
                printf("Malware Detected\n");
                printf("Name : %s\n", rule.name ? rule.name : "(unknown)");
                printf("Description : %s\n", rule.description ? rule.description : "(none)");
            }
            freeRule(&rule);
        }
    } while (FindNextFileA(findHandle, &findData));

    FindClose(findHandle);
    return foundCount;
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        printf("Usage: scanner <sourcefile> <rulesfolder>\n");
        return 1;
    }

    const char *sourceFile = argv[1];
    const char *rulesFolder = argv[2];

    char *content = readFile(sourceFile);
    if (!content) {
        fprintf(stderr, "Failed to open source file: %s\n", sourceFile);
        return 1;
    }

    int detected = scanRules(rulesFolder, content);
    if (detected == 0) {
        printf("No malware detected.\n");
    }

    free(content);
    return detected ? 0 : 0;
}
