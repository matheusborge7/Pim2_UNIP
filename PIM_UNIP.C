#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
  #include <direct.h>
  #define MKDIR(dir) _mkdir(dir)
#else
  #include <sys/stat.h>
  #include <sys/types.h>
  #define MKDIR(dir) mkdir(dir, 0755)
#endif

#define DATA_DIR "data"
#define ALUNOS_FILE DATA_DIR"/alunos.dat"
#define TURMAS_FILE DATA_DIR"/turmas.dat"

#define MAX_NOME 100
#define MAX_ALUNOS 1000
#define MAX_TURMAS 200

typedef struct {
    int id;
    char nome[MAX_NOME];
    char email[100];
    int turma_id; // 0 = sem turma
} Aluno;

typedef struct {
    int id;
    char nome[MAX_NOME];
    char descricao[200];
} Turma;

/* --- Funções utilitárias de persistência --- */

void ensure_data_dir() {
    // tenta criar, ignora se já existir
    MKDIR(DATA_DIR);
}

int file_exists(const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) return 0;
    fclose(f);
    return 1;
}

/* --- Alunos --- */
int carregar_alunos(Aluno alunos[], int *count) {
    *count = 0;
    if (!file_exists(ALUNOS_FILE)) return 0;
    FILE *f = fopen(ALUNOS_FILE, "rb");
    if (!f) return -1;
    fread(count, sizeof(int), 1, f);
    if (*count > 0 && *count <= MAX_ALUNOS) {
        fread(alunos, sizeof(Aluno), *count, f);
    } else {
        *count = 0;
    }
    fclose(f);
    return 0;
}

int salvar_alunos(Aluno alunos[], int count) {
    FILE *f = fopen(ALUNOS_FILE, "wb");
    if (!f) return -1;
    fwrite(&count, sizeof(int), 1, f);
    if (count > 0) fwrite(alunos, sizeof(Aluno), count, f);
    fclose(f);
    return 0;
}

int next_aluno_id(Aluno alunos[], int count) {
    int max = 0;
    for (int i=0;i<count;i++) if (alunos[i].id > max) max = alunos[i].id;
    return max + 1;
}

/* --- Turmas --- */
int carregar_turmas(Turma turmas[], int *count) {
    *count = 0;
    if (!file_exists(TURMAS_FILE)) return 0;
    FILE *f = fopen(TURMAS_FILE, "rb");
    if (!f) return -1;
    fread(count, sizeof(int), 1, f);
    if (*count > 0 && *count <= MAX_TURMAS) {
        fread(turmas, sizeof(Turma), *count, f);
    } else {
        *count = 0;
    }
    fclose(f);
    return 0;
}

int salvar_turmas(Turma turmas[], int count) {
    FILE *f = fopen(TURMAS_FILE, "wb");
    if (!f) return -1;
    fwrite(&count, sizeof(int), 1, f);
    if (count > 0) fwrite(turmas, sizeof(Turma), count, f);
    fclose(f);
    return 0;
}

int next_turma_id(Turma turmas[], int count) {
    int max = 0;
    for (int i=0;i<count;i++) if (turmas[i].id > max) max = turmas[i].id;
    return max + 1;
}

/* --- Interface CLI --- */
void adicionar_aluno(Aluno alunos[], int *count) {
    if (*count >= MAX_ALUNOS) {
        printf("Limite de alunos atingido.\n");
        return;
    }
    Aluno a;
    memset(&a,0,sizeof(Aluno));
    a.id = next_aluno_id(alunos, *count);
    printf("Nome do aluno: ");
    getchar(); // consome newline pendente
    fgets(a.nome, MAX_NOME, stdin);
    a.nome[strcspn(a.nome, "\n")] = '\0';
    printf("Email: ");
    fgets(a.email, sizeof(a.email), stdin);
    a.email[strcspn(a.email, "\n")] = '\0';
    a.turma_id = 0;
    alunos[*count] = a;
    (*count)++;
    if (salvar_alunos(alunos, *count) == 0) {
        printf("Aluno adicionado e salvo (ID=%d).\n", a.id);
    } else {
        printf("Erro ao salvar alunos.\n");
    }
}

void listar_alunos(Aluno alunos[], int count) {
    if (count == 0) {
        printf("Nenhum aluno cadastrado.\n");
        return;
    }
    printf("=== Alunos ===\n");
    for (int i=0;i<count;i++) {
        printf("ID: %d | Nome: %s | Email: %s | Turma ID: %d\n",
               alunos[i].id, alunos[i].nome, alunos[i].email, alunos[i].turma_id);
    }
}

/* --- Turmas (CRUD simples) --- */
void adicionar_turma(Turma turmas[], int *count) {
    if (*count >= MAX_TURMAS) {
        printf("Limite de turmas atingido.\n");
        return;
    }
    Turma t;
    memset(&t,0,sizeof(Turma));
    t.id = next_turma_id(turmas, *count);
    printf("Nome da turma: ");
    getchar(); // consome newline
    fgets(t.nome, MAX_NOME, stdin);
    t.nome[strcspn(t.nome, "\n")] = '\0';
    printf("Descricao curta: ");
    fgets(t.descricao, sizeof(t.descricao), stdin);
    t.descricao[strcspn(t.descricao, "\n")] = '\0';
    turmas[*count] = t;
    (*count)++;
    if (salvar_turmas(turmas, *count) == 0) {
        printf("Turma adicionada e salva (ID=%d).\n", t.id);
    } else {
        printf("Erro ao salvar turmas.\n");
    }
}

void listar_turmas(Turma turmas[], int count) {
    if (count == 0) {
        printf("Nenhuma turma cadastrada.\n");
        return;
    }
    printf("=== Turmas ===\n");
    for (int i=0;i<count;i++) {
        printf("ID: %d | Nome: %s | Desc: %s\n",
               turmas[i].id, turmas[i].nome, turmas[i].descricao);
    }
}

/* --- Associar aluno a turma --- */
void associar_aluno_turma(Aluno alunos[], int a_count, Turma turmas[], int t_count) {
    if (a_count == 0 || t_count == 0) {
        printf("É necessário ter ao menos um aluno e uma turma cadastrados.\n");
        return;
    }
    int aid, tid;
    listar_alunos(alunos, a_count);
    printf("Digite o ID do aluno: ");
    scanf("%d", &aid);
    int ai = -1;
    for (int i=0;i<a_count;i++) if (alunos[i].id == aid) { ai = i; break; }
    if (ai == -1) { printf("Aluno não encontrado.\n"); return; }
    listar_turmas(turmas, t_count);
    printf("Digite o ID da turma: ");
    scanf("%d", &tid);
    int ti = -1;
    for (int i=0;i<t_count;i++) if (turmas[i].id == tid) { ti = i; break; }
    if (ti == -1) { printf("Turma não encontrada.\n"); return; }
    alunos[ai].turma_id = turmas[ti].id;
    if (salvar_alunos(alunos, a_count) == 0) {
        printf("Aluno associado à turma com sucesso.\n");
    } else {
        printf("Erro ao salvar associação.\n");
    }
}

/* --- Menu principal --- */
void menu() {
    ensure_data_dir();

    Aluno alunos[MAX_ALUNOS];
    Turma turmas[MAX_TURMAS];
    int a_count = 0, t_count = 0;

    carregar_alunos(alunos, &a_count);
    carregar_turmas(turmas, &t_count);

    int opt = 0;
    while (1) {
        printf("\n=== Sistema Acadêmico (MVP) ===\n");
        printf("1. Adicionar aluno\n");
        printf("2. Listar alunos\n");
        printf("3. Adicionar turma\n");
        printf("4. Listar turmas\n");
        printf("5. Associar aluno -> turma\n");
        printf("0. Sair\n");
        printf("Escolha: ");
        if (scanf("%d", &opt) != 1) { 
            printf("Entrada inválida. Saindo.\n"); break;
        }
        switch (opt) {
            case 1: adicionar_aluno(alunos, &a_count); break;
            case 2: listar_alunos(alunos, a_count); break;
            case 3: adicionar_turma(turmas, &t_count); break;
            case 4: listar_turmas(turmas, t_count); break;
            case 5: associar_aluno_turma(alunos, a_count, turmas, t_count); break;
            case 0: printf("Encerrando...\n"); return;
            default: printf("Opção inválida.\n");
        }
    }
}

int main() {
    menu();
    return 0;
}
