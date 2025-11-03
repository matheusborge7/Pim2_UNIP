#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <ctype.h>

/* --- Definições Globais (Constantes) --- */
#define ARQUIVO_USUARIOS "usuarios.txt"
#define TAM_BUF 256
#define TEMPO_BLOQUEIO 30
#define MAX_USUARIOS 1000
#define MAX_TENTATIVAS 1000
#define MAX_USERS 512          
#define MAX_TENTATIVAS_CAP 512  

/* --- Tipos de dados customizados --- */
typedef unsigned char uint8;
typedef unsigned int uint32;
typedef unsigned long long uint64;

/*
  Implementação do SHA-256 (Criptografia de Senha)
*/
#define ROTRIGHT(a,b) (((a) >> (b)) | ((a) << (32-(b))))
#define CH(x,y,z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x) (ROTRIGHT(x,2) ^ ROTRIGHT(x,13) ^ ROTRIGHT(x,22))
#define EP1(x) (ROTRIGHT(x,6) ^ ROTRIGHT(x,11) ^ ROTRIGHT(x,25))
#define SIG0(x) (ROTRIGHT(x,7) ^ ROTRIGHT(x,18) ^ ((x) >> 3))
#define SIG1(x) (ROTRIGHT(x,17) ^ ROTRIGHT(x,19) ^ ((x) >> 10))

static const uint32 k[64] = {
  0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
  0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
  0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
  0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
  0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
  0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
  0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
  0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

typedef struct {
    uint8 data[64];
    uint32 datalen;
    uint64 bitlen;
    uint32 state[8];
} SHA256_CTX;

void sha256_transform(SHA256_CTX *ctx, const uint8 data[]) {
    uint32 a,b,c,d,e,f,g,h,i,j,t1,t2,m[64];
    for (i=0,j=0; i<16; ++i, j+=4)
        m[i] = (data[j] << 24) | (data[j+1] << 16) | (data[j+2] << 8) | (data[j+3]);
    for (; i<64; ++i)
        m[i] = SIG1(m[i-2]) + m[i-7] + SIG0(m[i-15]) + m[i-16];
    a = ctx->state[0]; b = ctx->state[1]; c = ctx->state[2]; d = ctx->state[3];
    e = ctx->state[4]; f = ctx->state[5]; g = ctx->state[6]; h = ctx->state[7];
    for (i=0; i<64; ++i) {
        t1 = h + EP1(e) + CH(e,f,g) + k[i] + m[i];
        t2 = EP0(a) + MAJ(a,b,c);
        h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
    }
    ctx->state[0] += a; ctx->state[1] += b; ctx->state[2] += c; ctx->state[3] += d;
    ctx->state[4] += e; ctx->state[5] += f; ctx->state[6] += g; ctx->state[7] += h;
}

void sha256_init(SHA256_CTX *ctx) {
    ctx->datalen = 0; ctx->bitlen = 0;
    ctx->state[0] = 0x6a09e667; ctx->state[1] = 0xbb67ae85; ctx->state[2] = 0x3c6ef372; ctx->state[3] = 0xa54ff53a;
    ctx->state[4] = 0x510e527f; ctx->state[5] = 0x9b05688c; ctx->state[6] = 0x1f83d9ab; ctx->state[7] = 0x5be0cd19;
}

void sha256_update(SHA256_CTX *ctx, const uint8 data[], size_t len) {
    uint32 i;
    for (i=0; i<len; ++i) {
        ctx->data[ctx->datalen] = data[i]; ctx->datalen++;
        if (ctx->datalen == 64) { sha256_transform(ctx, ctx->data); ctx->bitlen += 512; ctx->datalen = 0; }
    }
}

void sha256_final(SHA256_CTX *ctx, uint8 hash[]) {
    uint32 i = ctx->datalen;
    if (ctx->datalen < 56) { ctx->data[i++] = 0x80; while (i < 56) ctx->data[i++] = 0x00; }
    else { ctx->data[i++] = 0x80; while (i < 64) ctx->data[i++] = 0x00; sha256_transform(ctx, ctx->data); memset(ctx->data, 0, 56); }
    ctx->bitlen += ctx->datalen * 8;
    ctx->data[63] = ctx->bitlen;
    ctx->data[62] = ctx->bitlen >> 8;
    ctx->data[61] = ctx->bitlen >> 16;
    ctx->data[60] = ctx->bitlen >> 24;
    ctx->data[59] = ctx->bitlen >> 32;
    ctx->data[58] = ctx->bitlen >> 40;
    ctx->data[57] = ctx->bitlen >> 48;
    ctx->data[56] = ctx->bitlen >> 56;
    sha256_transform(ctx, ctx->data);
    for (i=0;i<4;i++) {
        hash[i]      = (ctx->state[0] >> (24 - i * 8)) & 0x000000ff;
        hash[i + 4]  = (ctx->state[1] >> (24 - i * 8)) & 0x000000ff;
        hash[i + 8]  = (ctx->state[2] >> (24 - i * 8)) & 0x000000ff;
        hash[i + 12] = (ctx->state[3] >> (24 - i * 8)) & 0x000000ff;
        hash[i + 16] = (ctx->state[4] >> (24 - i * 8)) & 0x000000ff;
        hash[i + 20] = (ctx->state[5] >> (24 - i * 8)) & 0x000000ff;
        hash[i + 24] = (ctx->state[6] >> (24 - i * 8)) & 0x000000ff;
        hash[i + 28] = (ctx->state[7] >> (24 - i * 8)) & 0x000000ff;
    }
}

/* (SHA-256) Função principal para transformar uma string em hash */
void sha256_string(const char *str, char out_hex[65]) {
    uint8 hash[32]; SHA256_CTX ctx; sha256_init(&ctx); sha256_update(&ctx, (const uint8*)str, strlen(str)); sha256_final(&ctx, hash);
    for (int i = 0; i < 32; i++)
        sprintf(out_hex + (i*2), "%02x", hash[i]);
    out_hex[64] = 0;
}
/* ===========================================================
  Fim do SHA-256
=========================================================== */


/* --- Estrutura de dados principal (Professor e Aluno) --- */
typedef struct Usuario {
    char nome[128];
    char email[128];
    char senha_hash[65];
    char tipo[16];      /* "aluno" ou "professor" */
    char cursos[512];
    char notas[1024];
    char aulas[512];
    char alunos[1024];
} Usuario;

/* --- Arrays globais (variáveis) --- */
static Usuario *usuarios = NULL;          /* Guarda todos os usuários em memória */
static size_t usuarios_count = 0;

static char **tentativa_emails = NULL;     /* Guarda emails que tentaram logar */
static int *tentativa_cont = NULL;         /* Guarda a contagem de tentativas */
static int *tentativa_bloqueado = NULL;    /* Guarda se o email está bloqueado (1) ou não (0) */
static time_t *tentativa_tempo = NULL;     /* Guarda a hora que o bloqueio começou */
static size_t tentativas_count = 0;

/* --- Funções de Ajuda (Helpers) --- */

/* (Helper) Copia uma string */
static char *xstrdup(const char *s) {
    if (!s) return NULL;
    size_t n = strlen(s) + 1;
    char *p = (char*)malloc(n);
    if (p) memcpy(p, s, n);
    return p;
}

/* (Helper) Garante que o arquivo usuarios.txt exista */
void garantir_arquivo() {
    FILE *f = fopen(ARQUIVO_USUARIOS, "a");
    if (f) fclose(f);
}

/* (Helper) Libera memória do array de usuários */
void liberar_usuarios_buffer() {
    if (usuarios) {
        free(usuarios);
        usuarios = NULL;
        usuarios_count = 0;
    }
}

/* --- Funções de Leitura/Escrita de Arquivo --- */

/* Carrega todos os usuários do arquivo "usuarios.txt" para a memória */
/* (Usa parser manual para campos vazios ||) */
void carregar_usuarios() {
    garantir_arquivo();
    FILE *f = fopen(ARQUIVO_USUARIOS, "r");
    if (!f) return;
    char linha[TAM_BUF];
    usuarios_count = 0; 
    
    while (fgets(linha, sizeof(linha), f)) {
        linha[strcspn(linha, "\n")] = 0;
        if (strlen(linha) == 0) continue;
        
        if (usuarios_count >= (size_t)MAX_USERS) {
            printf("Aviso: limite MAX_USERS atingido. Ignorando usuários adicionais no arquivo.\n");
            break;
        }
        
        Usuario u; memset(&u, 0, sizeof(Usuario));
        
        char *parts[8] = {0};
        int idx = 0;
        char *current = linha; 

        for (idx = 0; idx < 8; idx++) {
            char *next_sep = strchr(current, '|'); 
            
            if (next_sep) {
                *next_sep = '\0';      
                parts[idx] = current;  
                current = next_sep + 1; 
            } else {
                parts[idx] = current;
                break; 
            }
        }
        
        int part_count = idx + 1;
        if (idx == 7 && part_count < 8) part_count = 8; 
        
        if (part_count >= 4) { 
            strncpy(u.nome, parts[0], sizeof(u.nome)-1);
            strncpy(u.email, parts[1], sizeof(u.email)-1);
            strncpy(u.senha_hash, parts[2], sizeof(u.senha_hash)-1);
            strncpy(u.tipo, parts[3], sizeof(u.tipo)-1);
            
            if (part_count > 4 && parts[4]) strncpy(u.cursos, parts[4], sizeof(u.cursos)-1);
            if (part_count > 5 && parts[5]) strncpy(u.notas, parts[5], sizeof(u.notas)-1);
            if (part_count > 6 && parts[6]) strncpy(u.aulas, parts[6], sizeof(u.aulas)-1);
            if (part_count > 7 && parts[7]) strncpy(u.alunos, parts[7], sizeof(u.alunos)-1);
            
            usuarios[usuarios_count++] = u;
        }
    }
    fclose(f);
}

/* Salva todos os usuários da memória de volta para o "usuarios.txt" */
void salvar_usuarios() {
    FILE *f = fopen(ARQUIVO_USUARIOS, "w");
    if (!f) { printf("Erro ao salvar usuários.\n"); return; }
    for (size_t i=0;i<usuarios_count;i++) {
        Usuario *u = &usuarios[i];
        fprintf(f, "%s|%s|%s|%s|%s|%s|%s|%s\n",
            u->nome, u->email, u->senha_hash, u->tipo,
            u->cursos[0] ? u->cursos : "",
            u->notas[0] ? u->notas : "",
            u->aulas[0] ? u->aulas : "",
            u->alunos[0] ? u->alunos : "");
    }
    fclose(f);
}

/* Busca um usuário no array da memória pelo email */
Usuario* encontrar_usuario_por_email(const char *email) {
    if (!email) return NULL;
    for (size_t i=0;i<usuarios_count;i++) if (strcasecmp(usuarios[i].email, email) == 0) return &usuarios[i];
    return NULL;
}


/* --- Funções de Controle de Tentativa de Login --- */

/* (Login) Acha o índice de um email na lista de tentativas */
int index_tentativa(const char *email) {
    if (!email) return -1;
    for (size_t i=0;i<tentativas_count;i++) if (tentativa_emails[i] && strcasecmp(tentativa_emails[i], email) == 0) return (int)i;
    return -1;
}

/* (Login) Aloca memória para os arrays de tentativa */
int init_tentativas_arrays() {
    if (tentativa_emails) return 1; 
    tentativa_emails = (char**)malloc(sizeof(char*) * MAX_TENTATIVAS_CAP);
    tentativa_cont = (int*)malloc(sizeof(int) * MAX_TENTATIVAS_CAP);
    tentativa_bloqueado = (int*)malloc(sizeof(int) * MAX_TENTATIVAS_CAP);
    tentativa_tempo = (time_t*)malloc(sizeof(time_t) * MAX_TENTATIVAS_CAP);
    if (!tentativa_emails || !tentativa_cont || !tentativa_bloqueado || !tentativa_tempo) {
        free(tentativa_emails); free(tentativa_cont); free(tentativa_bloqueado); free(tentativa_tempo);
        tentativa_emails = NULL; tentativa_cont = NULL; tentativa_bloqueado = NULL; tentativa_tempo = NULL;
        return 0;
    }
    for (size_t i=0;i<MAX_TENTATIVAS_CAP;i++) tentativa_emails[i] = NULL;
    tentativas_count = 0;
    return 1;
}

/* (Login) Cria um registro de tentativa para um email (se não existir) */
void garantir_tentativa(const char *email) {
    if (!email) return;
    if (!init_tentativas_arrays()) { printf("Erro ao inicializar tentativas (memória insuficiente).\n"); return; }
    if (index_tentativa(email) >= 0) return;
    if (tentativas_count >= (size_t)MAX_TENTATIVAS_CAP) {
        printf("Limite de tentativa entries atingido; não será possível registrar nova tentativa para %s\n", email);
        return;
    }
    tentativa_emails[tentativas_count] = xstrdup(email);
    tentativa_cont[tentativas_count] = 0;
    tentativa_bloqueado[tentativas_count] = 0;
    tentativa_tempo[tentativas_count] = 0;
    tentativas_count++;
}

/* (Login) Verifica se o email não está bloqueado por tempo */
int pode_tentar_login(const char *email, int *tempo_restante) {
    garantir_tentativa(email);
    int idx = index_tentativa(email);
    if (idx < 0) { *tempo_restante = 0; return 1; }
    if (tentativa_bloqueado[idx]) {
        time_t agora = time(NULL);
        double diff = difftime(agora, tentativa_tempo[idx]);
        if (diff < TEMPO_BLOQUEIO) { *tempo_restante = (int)(TEMPO_BLOQUEIO - diff); return 0; }
        tentativa_cont[idx] = 0; tentativa_bloqueado[idx] = 0; tentativa_tempo[idx] = 0; *tempo_restante = 0; return 1;
    }
    *tempo_restante = 0; return 1;
}

/* (Login) Registra uma senha errada e bloqueia se passar do limite */
void registrar_tentativa_errada(const char *email) {
    garantir_tentativa(email);
    int idx = index_tentativa(email);
    if (idx < 0) return;
    tentativa_cont[idx]++;
    if (tentativa_cont[idx] >= MAX_TENTATIVAS_CAP) { tentativa_bloqueado[idx] = 1; tentativa_tempo[idx] = time(NULL); }
}

/* (Login) Zera as tentativas após login com sucesso */
void reset_tentativas(const char *email) {
    garantir_tentativa(email);
    int idx = index_tentativa(email);
    if (idx < 0) return;
    tentativa_cont[idx] = 0; tentativa_bloqueado[idx] = 0; tentativa_tempo[idx] = 0;
}

/* --- Funções Utilitárias (manipulação de strings) --- */

/* (Helper) Remove espaços em branco do início e fim de uma string */
void trim(char *s) {
    if (!s) return;
    char *p = s; while (*p && isspace((unsigned char)*p)) p++;
    if (p != s) memmove(s, p, strlen(p)+1);
    size_t len = strlen(s); while (len>0 && isspace((unsigned char)s[len-1])) s[--len]=0;
}

/* (Helper) Validação simples de email (contém @ e .) */
int validar_email(const char *email) { return (email && strchr(email, '@') && strchr(email, '.')) ? 1 : 0; }


/* --- Funções de Manipulação de Dados do Usuário --- */

/* (Helper) Verifica se um email está numa lista (string separada por ';') */
int email_na_lista(const char *lista, const char *email) {
    if (!lista || !*lista || !email) return 0;
    char tmp[1024]; strncpy(tmp, lista, sizeof(tmp)-1); tmp[sizeof(tmp)-1]=0;
    char *t = strtok(tmp, ";"); while (t) { if (strcasecmp(t, email)==0) return 1; t = strtok(NULL, ";"); } return 0;
}

/* (Helper) Adiciona um email na lista (string separada por ';') */
void adicionar_email_na_lista(char *lista, size_t max_len, const char *email) {
    if (!lista || !email) return;
    if (email_na_lista(lista, email)) return;
    size_t need = strlen(lista) + strlen(email) + 2; 
    if (need > max_len) { printf("Espaço insuficiente para adicionar item.\n"); return; }
    if (strlen(lista)) strcat(lista, ";");
    strcat(lista, email);
}

/* (Helper) Adiciona um curso para o aluno (limite de 3) */
void adicionar_curso_em_usuario(Usuario *al, const char *curso) {
    if (!al || !curso) return;
    int count = 0;
    if (strlen(al->cursos)) { char tmp[512]; strcpy(tmp, al->cursos); char *t = strtok(tmp, ";"); while (t) { count++; t = strtok(NULL, ";"); } }
    
    // Regra de negócio: Aluno só pode ter 3 cursos
    if (count >= 3) { 
        printf("Aluno já possui 3 cursos.\n"); 
        return; 
    }
    
    size_t need = strlen(al->cursos) + strlen(curso) + 2;
    if (need > sizeof(al->cursos)) { printf("Espaço insuficiente para adicionar curso.\n"); return; }
    if (strlen(al->cursos)) strcat(al->cursos, ";");
    strcat(al->cursos, curso);
}

/* (Helper) Adiciona ou atualiza a nota de um curso para o aluno */
void adicionar_nota_em_usuario(Usuario *al, const char *curso, double nota) {
    if (!al || !curso) return;
    char entrada[256]; snprintf(entrada, sizeof(entrada), "%s:%.1f", curso, nota);
    if (strlen(al->notas)) {
        char tmp[1024]; strcpy(tmp, al->notas); char *p = strtok(tmp, ","); char novo[1024] = ""; int atualizado = 0;
        while (p) {
            char nome_curso[256]; double v;
            if (sscanf(p, "%255[^:]:%lf", nome_curso, &v) == 2) {
                if (strcasecmp(nome_curso, curso) == 0) {
                    if (strlen(novo)) strcat(novo, ",");
                        strcat(novo, entrada);
                        atualizado = 1;
                } else {
                    if (strlen(novo)) strcat(novo, ",");
                        strcat(novo, p);
                }
            }
            p = strtok(NULL, ",");
        }
        if (atualizado) { strncpy(al->notas, novo, sizeof(al->notas)-1); return; }
    }
    size_t need = strlen(al->notas) + strlen(entrada) + 2;
    if (need > sizeof(al->notas)) { printf("Espaço insuficiente para adicionar nota.\n"); return; }
    if (strlen(al->notas)) strcat(al->notas, ",");
    strcat(al->notas, entrada);
}

/* (Helper) Adiciona um link de aula para o aluno */
void adicionar_aula_em_usuario(Usuario *al, const char *aula) {
    if (!al || !aula) return;
    size_t need = strlen(al->aulas) + strlen(aula) + 2;
    if (need > sizeof(al->aulas)) { printf("Espaço insuficiente para adicionar aula.\n"); return; }
    if (strlen(al->aulas)) strcat(al->aulas, ";");
    strcat(al->aulas, aula);
}


/* --- Funções Principais (Telas do Sistema) --- */

/* Função Principal: Login de Usuário */
int login_usuario_index(char out_email[128]) {
    carregar_usuarios();
    char email[128], senha[128];
    printf("\n=== Login ===\n");
    printf("Email: "); if (!fgets(email, sizeof(email), stdin)) return -1; email[strcspn(email, "\n")] = 0; trim(email);
    for (char *p=email; *p; ++p) *p = tolower(*p);
    
    int tempo_restante=0; 
    if (!pode_tentar_login(email, &tempo_restante)) { 
        printf("Conta bloqueada. Tente novamente em %d segundos.\n", tempo_restante); 
        return -1; 
    }
    
    printf("Senha: "); if (!fgets(senha, sizeof(senha), stdin)) return -1; senha[strcspn(senha, "\n")] = 0;
    
    char hash[65]; sha256_string(senha, hash);

    for (size_t i=0;i<usuarios_count;i++) {
        if (strcasecmp(usuarios[i].email, email) == 0) {
            if (strcmp(usuarios[i].senha_hash, hash) == 0) {
                reset_tentativas(email);
                printf("Bem-vindo(a) %s!\n\n", usuarios[i].nome);
                if (out_email) strncpy(out_email, usuarios[i].email, 128);
                return (int)i;
            } else {
                printf("Email ou senha incorretos.\n");
                registrar_tentativa_errada(email);
                return -1;
            }
        }
    }
    printf("Email ou senha incorretos.\n");
    registrar_tentativa_errada(email);
    return -1;
}

/* Função Principal: Cadastro de Usuário */
void cadastrar_usuario() {
    carregar_usuarios();
    if (usuarios_count >= (size_t)MAX_USERS) { printf("Capacidade máxima de usuários atingida. Não é possível cadastrar mais.\n"); return; }
    char nome[128], email[128], senha[128], tipo_buf[16];
    printf("\n=== Cadastro ===\n");
    printf("Nome: "); if (!fgets(nome, sizeof(nome), stdin)) return; nome[strcspn(nome, "\n")] = 0; trim(nome);
    printf("Email: "); if (!fgets(email, sizeof(email), stdin)) return; email[strcspn(email, "\n")] = 0; trim(email);
    for (char *p=email; *p; ++p) *p = tolower(*p);
    if (!validar_email(email)) { printf("Email inválido.\n"); return; }
    if (encontrar_usuario_por_email(email)) { printf("Email já cadastrado.\n"); return; }
    printf("Senha: "); if (!fgets(senha, sizeof(senha), stdin)) return; senha[strcspn(senha, "\n")] = 0;
    printf("Tipo (A = Aluno, P = Professor): "); if (!fgets(tipo_buf, sizeof(tipo_buf), stdin)) return; tipo_buf[strcspn(tipo_buf, "\n")] = 0; trim(tipo_buf);
    char tipo_c = toupper((unsigned char)tipo_buf[0]); if (tipo_c != 'A' && tipo_c != 'P') { printf("Tipo inválido.\n"); return; }

    Usuario u; memset(&u, 0, sizeof(Usuario)); strncpy(u.nome, nome, sizeof(u.nome)-1); strncpy(u.email, email, sizeof(u.email)-1);
    char hash[65]; sha256_string(senha, hash); strncpy(u.senha_hash, hash, sizeof(u.senha_hash)-1);
    strcpy(u.tipo, (tipo_c=='A')?"aluno":"professor");

    usuarios[usuarios_count++] = u;
    salvar_usuarios();
    printf("Cadastro realizado com sucesso!\n");
}

/* --- Menu do Aluno --- */
void menu_aluno(const char *email_usuario) {
    char opcao[8];
    while (1) {
        carregar_usuarios();
        Usuario *usuario = encontrar_usuario_por_email(email_usuario);
        if (!usuario) { printf("Usuário não encontrado (ou foi removido). Saindo do menu.\n"); return; }

        printf("=== Menu Aluno ===\n1 - Ver informações\n2 - Ver cursos\n3 - Ver notas\n4 - Ver aulas\n0 - Sair\nEscolha uma opção: ");
        if (!fgets(opcao, sizeof(opcao), stdin))
        break;
    trim(opcao);
        if (strcmp(opcao, "1") == 0) printf("\nNome: %s\nEmail: %s\n\n", usuario->nome, usuario->email);
        else if (strcmp(opcao, "2") == 0) {
            if (strlen(usuario->cursos)) { char tmp[512]; strcpy(tmp, usuario->cursos); char *t = strtok(tmp, ";"); printf("\nSeus cursos:\n"); while (t) { printf("- %s\n", t); t = strtok(NULL, ";"); } printf("\n"); }
            else printf("Você não está matriculado em nenhum curso.\n\n");
        }
        else if (strcmp(opcao, "3") == 0) {
            if (strlen(usuario->notas)) { char tmp[1024]; strcpy(tmp, usuario->notas); char *t = strtok(tmp, ","); printf("\nSuas notas:\n"); while (t) { printf("%s\n", t); t = strtok(NULL, ","); } printf("\n"); }
            else printf("Nenhuma nota registrada.\n\n");
        }
        else if (strcmp(opcao, "4") == 0) {
            if (strlen(usuario->aulas)) { char tmp[512]; strcpy(tmp, usuario->aulas); char *t = strtok(tmp, ";"); printf("\nSuas aulas:\n"); while (t) { printf("- %s\n", t); t = strtok(NULL, ";"); } printf("\n"); }
            else printf("Nenhuma aula cadastrada.\n\n");
        }
        else if (strcmp(opcao, "0") == 0) break; else printf("Opção inválida.\n");
    }
}

/* --- Menu do Professor --- */
void menu_professor(const char *email_prof) {
    char opcao[8];
    while (1) {
        carregar_usuarios(); 
        Usuario *professor = encontrar_usuario_por_email(email_prof);
        if (!professor) { printf("Usuário não encontrado (ou foi removido). Saindo do menu.\n"); return; }

        printf("=== Menu Professor ===\n1 - Ver informações\n2 - Adicionar aluno\n3 - Adicionar curso para aluno\n4 - Adicionar nota para aluno\n5 - Adicionar aula para aluno\n6 - Ver alunos e dados\n0 - Sair\nEscolha uma opção: ");
        if (!fgets(opcao, sizeof(opcao), stdin))
        break;
    trim(opcao);
        
        /* Opção 1: Ver informações */
        if (strcmp(opcao, "1") == 0) printf("\nNome: %s\nEmail: %s\n\n", professor->nome, professor->email);
        
        /* Opção 2: Adicionar aluno (na lista do professor) */
        else if (strcmp(opcao, "2") == 0) {
            char email_aluno[128]; printf("Digite o email do aluno para adicionar: "); if (!fgets(email_aluno, sizeof(email_aluno), stdin)) continue; email_aluno[strcspn(email_aluno, "\n")] = 0; trim(email_aluno); for (char *p=email_aluno; *p; ++p) *p = tolower(*p);
            
            Usuario *al = encontrar_usuario_por_email(email_aluno); 
            if (al && strcmp(al->tipo, "aluno") == 0) {
                adicionar_email_na_lista(professor->alunos, sizeof(professor->alunos), email_aluno);
                salvar_usuarios(); 
                printf("Aluno adicionado com sucesso!\n");
            } else printf("Aluno não encontrado.\n");
        }
        
        /* Opção 3: Adicionar curso para um aluno */
        else if (strcmp(opcao, "3") == 0) {
            if (strlen(professor->alunos) == 0) { printf("Você não tem alunos adicionados.\n\n"); continue; } 
            char email_aluno[128]; printf("Digite o email do aluno para adicionar curso: "); if (!fgets(email_aluno, sizeof(email_aluno), stdin)) continue; email_aluno[strcspn(email_aluno, "\n")] = 0; trim(email_aluno); for (char *p=email_aluno; *p; ++p) *p = tolower(*p);
            if (!email_na_lista(professor->alunos, email_aluno)) { printf("Aluno não está na sua lista.\n"); continue; }
            
            Usuario *al = encontrar_usuario_por_email(email_aluno); if (!al) { printf("Aluno não encontrado.\n"); continue; }
            char curso[128]; printf("Digite o nome do curso: "); if (!fgets(curso, sizeof(curso), stdin)) continue; curso[strcspn(curso, "\n")] = 0; trim(curso);
            adicionar_curso_em_usuario(al, curso); 
            salvar_usuarios(); 
            printf("Curso adicionado com sucesso!\n");
        }
        
        /* Opção 4: Adicionar nota para um aluno */
        else if (strcmp(opcao, "4") == 0) {
            if (strlen(professor->alunos) == 0) { printf("Você não tem alunos adicionados.\n\n"); continue; }
            char email_aluno[128]; printf("Digite o email do aluno para adicionar nota: "); if (!fgets(email_aluno, sizeof(email_aluno), stdin)) continue; email_aluno[strcspn(email_aluno, "\n")] = 0; trim(email_aluno); for (char *p=email_aluno; *p; ++p) *p = tolower(*p);
            if (!email_na_lista(professor->alunos, email_aluno)) { printf("Aluno não está na sua lista.\n"); continue; }
            
            Usuario *al = encontrar_usuario_por_email(email_aluno); if (!al) { printf("Aluno não encontrado.\n"); continue; }
            if (!strlen(al->cursos)) { printf("Aluno não possui cursos.\n"); continue; }
            char tmp[512]; strcpy(tmp, al->cursos); char *lista[32]; int n=0; char *x = strtok(tmp, ";"); while (x && n<32) { lista[n++] = x; x = strtok(NULL, ";"); }
            
            for (int i=0;i<n;i++) {
                printf("%d - %s\n", i+1, lista[i]); 
            }
            
            char escolha[8]; printf("Escolha o número do curso para adicionar nota: "); if (!fgets(escolha, sizeof(escolha), stdin)) continue; trim(escolha); int idx = atoi(escolha); if (idx<1 || idx>n) { printf("Opção inválida.\n"); continue; }
            char nota_str[32]; printf("Digite a nota (0-10): "); if (!fgets(nota_str, sizeof(nota_str), stdin)) continue; nota_str[strcspn(nota_str, "\n")] = 0; trim(nota_str);
            double nota = atof(nota_str); if (nota < 0.0 || nota > 10.0) { printf("Nota inválida.\n"); continue; }
            adicionar_nota_em_usuario(al, lista[idx-1], nota); 
            salvar_usuarios(); 
            printf("Nota adicionada com sucesso!\n");
        }
        
        /* Opção 5: Adicionar aula para um aluno */
        else if (strcmp(opcao, "5") == 0) {
            if (strlen(professor->alunos) == 0) { printf("Você não tem alunos adicionados.\n\n"); continue; }
            char email_aluno[128]; printf("Digite o email do aluno para adicionar aula: "); if (!fgets(email_aluno, sizeof(email_aluno), stdin)) continue; email_aluno[strcspn(email_aluno, "\n")] = 0; trim(email_aluno); for (char *p=email_aluno; *p; ++p) *p = tolower(*p);
            if (!email_na_lista(professor->alunos, email_aluno)) { printf("Aluno não está na sua lista.\n"); continue; }
            
            Usuario *al = encontrar_usuario_por_email(email_aluno); if (!al) { printf("Aluno não encontrado.\n"); continue; }
            char aula[256]; printf("Digite o link da aula: "); if (!fgets(aula, sizeof(aula), stdin)) continue; aula[strcspn(aula, "\n")] = 0; trim(aula);
            adicionar_aula_em_usuario(al, aula); 
            salvar_usuarios(); 
            printf("Aula adicionada com sucesso!\n");
        }
        
        /* Opção 6: Ver todos os alunos e seus dados */
        else if (strcmp(opcao, "6") == 0) {
            if (strlen(professor->alunos) == 0) { printf("Você não tem alunos adicionados.\n\n"); continue; }
            printf("\n=== Alunos e dados ===\n");
            char tmp[1024]; strncpy(tmp, professor->alunos, sizeof(tmp)-1); tmp[sizeof(tmp)-1]=0;
            char *t = strtok(tmp, ";");
            while (t) {
                Usuario *al = encontrar_usuario_por_email(t); 
                if (al) {
                    printf("\nAluno: %s - %s\n", al->nome, al->email);
                    printf("Cursos: %s\n", strlen(al->cursos)? al->cursos : "Nenhum");
                    printf("Notas:\n");
                    if (strlen(al->notas)) { char ntmp[1024]; strcpy(ntmp, al->notas); char *p2 = strtok(ntmp, ","); while (p2) { printf("  %s\n", p2); p2 = strtok(NULL, ","); } }
                    else printf("  Nenhuma nota.\n");
                    printf("Aulas: %s\n", strlen(al->aulas)? al->aulas : "Nenhuma");
                } else printf("Aluno %s não encontrado.\n", t);
                t = strtok(NULL, ";");
            }
            printf("\n");
        }
        
        /* Opção 0: Sair do menu do professor */
        else if (strcmp(opcao, "0") == 0) break; 
        
        /* Opção Inválida */
        else printf("Opção inválida.\n");
    }
}

/* --- Funções de Inicialização e Limpeza do Programa --- */

/* Inicializa os arrays globais (aloca memória) */
int init_global_structs() {
    if (!usuarios) {
        usuarios = (Usuario*)malloc(sizeof(Usuario) * MAX_USERS);
        if (!usuarios) return 0;
        usuarios_count = 0;
    }
    if (!init_tentativas_arrays()) return 0;
    return 1;
}

/* Libera toda a memória (free) antes de fechar o programa */
void cleanup() {
    if (tentativa_emails) {
        for (size_t i=0;i<tentativas_count;i++) if (tentativa_emails[i]) free(tentativa_emails[i]);
    }
    free(tentativa_emails); tentativa_emails = NULL;
    free(tentativa_cont); tentativa_cont = NULL;
    free(tentativa_bloqueado); tentativa_bloqueado = NULL;
    free(tentativa_tempo); tentativa_tempo = NULL;
    tentativas_count = 0;
    liberar_usuarios_buffer();
}

/* --- Função Principal (main) --- */
int main() {
    /* Inicializa as estruturas */
    if (!init_global_structs()) {
        printf("Erro de inicialização: memória insuficiente.\n");
        return 1;
    }
    garantir_arquivo();
    carregar_usuarios();

    char opcao[8];
    
    /* Loop do menu principal (Login/Cadastro/Sair) */
    while (1) {
        printf("=== Sistema Acadêmico ===\n1 - Cadastrar\n2 - Login\n0 - Sair\nEscolha uma opção: ");
        if (!fgets(opcao, sizeof(opcao), stdin))
        break;
    trim(opcao);
        
        if (strcmp(opcao, "1") == 0) cadastrar_usuario();
        else if (strcmp(opcao, "2") == 0) {
            char current_email[128] = {0};
            int idx = login_usuario_index(current_email);
            
            if (idx >= 0) {
                Usuario *u = encontrar_usuario_por_email(current_email);
                if (!u) { printf("Erro: usuário não encontrado após login.\n"); continue; }
                
                /* Direciona para o menu correto (Aluno ou Professor) */
                if (strcmp(u->tipo, "aluno") == 0) menu_aluno(current_email);
                else menu_professor(current_email);
                
                salvar_usuarios(); 
                carregar_usuarios();
            }
        }
        else if (strcmp(opcao, "0") == 0) { printf("Saindo...\n"); break; }
        else printf("Opção inválida.\n");
    }

    /* Limpa a memória antes de sair */
    cleanup();
    return 0;
}