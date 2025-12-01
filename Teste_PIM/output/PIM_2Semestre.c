#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <ctype.h>
#include <locale.h>
#include <math.h> 

/* ========================================================================== */
/* CORREÇÃO DE COMPATIBILIDADE (WINDOWS / MINGW)                */
/* ========================================================================== */
#ifdef _WIN32
    /* No Windows, strcasecmp chama-se _stricmp */
    #define strcasecmp _stricmp
    #define strncasecmp _strnicmp

    /* Implementação manual do strtok_r para Windows (thread-safe tokenizer) */
    char *strtok_r(char *str, const char *delim, char **saveptr) {
        char *token;
        if (str == NULL) str = *saveptr;
        str += strspn(str, delim);
        if (*str == '\0') {
            *saveptr = str;
            return NULL;
        }
        token = str;
        str = strpbrk(token, delim);
        if (str == NULL) {
            *saveptr = strchr(token, '\0');
        } else {
            *str = '\0';
            *saveptr = str + 1;
        }
        return token;
    }
#endif
/* ========================================================================== */


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
    char feedback[1024]; /* NOVO CAMPO: Para Análise de Sentimento */
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

/* (Helper) Remove espaços em branco do início e fim de uma string */
void trim(char *s) {
    size_t len = strlen(s);
    if (len == 0) return;
    
    // Remove do final
    while (len > 0 && isspace((unsigned char)s[len - 1])) {
        s[--len] = '\0';
    }
    
    // Remove do início
    size_t start = 0;
    while (start < len && isspace((unsigned char)s[start])) {
        start++;
    }
    
    if (start > 0) {
        memmove(s, s + start, len - start + 1);
    }
}

/* (Helper) Verifica se um email está na lista de emails (separados por ';') */
int email_na_lista(const char *lista, const char *email) {
    if (!lista || !email || strlen(lista) == 0) return 0;
    char tmp[1024]; strncpy(tmp, lista, sizeof(tmp)-1); tmp[sizeof(tmp)-1] = 0;
    char *t = strtok(tmp, ";");
    while (t) {
        if (strcasecmp(t, email) == 0) return 1;
        t = strtok(NULL, ";");
    }
    return 0;
}

/* (Helper) Adiciona um email à lista de emails (separados por ';') */
void adicionar_email_na_lista(char *lista, size_t max_len, const char *email) {
    if (strlen(lista) == 0) {
        strncpy(lista, email, max_len - 1);
    } else if (!email_na_lista(lista, email)) {
        if (strlen(lista) + 1 + strlen(email) < max_len) {
            strcat(lista, ";");
            strcat(lista, email);
        }
    }
}

/* (Helper) Adiciona um curso ao usuário */
void adicionar_curso_em_usuario(Usuario *u, const char *curso) {
    if (strlen(u->cursos) == 0) {
        strncpy(u->cursos, curso, sizeof(u->cursos) - 1);
    } else {
        // Verifica se o curso já existe (simplificado: busca por substring)
        char tmp[512]; strncpy(tmp, u->cursos, sizeof(tmp)-1); tmp[sizeof(tmp)-1] = 0;
        char *t = strtok(tmp, ";");
        int encontrado = 0;
        while (t) {
            if (strcasecmp(t, curso) == 0) { encontrado = 1; break; }
            t = strtok(NULL, ";");
        }
        
        if (!encontrado) {
            if (strlen(u->cursos) + 1 + strlen(curso) < sizeof(u->cursos)) {
                strcat(u->cursos, ";");
                strcat(u->cursos, curso);
            }
        }
    }
}

/* (Helper) Adiciona uma nota ao usuário */
void adicionar_nota_em_usuario(Usuario *u, const char *curso, double nota) {
    char nota_str[128];
    snprintf(nota_str, sizeof(nota_str), "%s:%.2f", curso, nota);
    
    if (strlen(u->notas) == 0) {
        strncpy(u->notas, nota_str, sizeof(u->notas) - 1);
    } else {
        // Verifica se já existe nota para o curso e substitui (ou adiciona)
        char tmp[1024]; strncpy(tmp, u->notas, sizeof(tmp)-1); tmp[sizeof(tmp)-1] = 0;
        char *p = tmp;
        char *next_token;
        char *new_notas = (char*)malloc(sizeof(u->notas));
        new_notas[0] = '\0';
        int substituido = 0;
        
        char *token = strtok_r(p, ",", &next_token);
        while (token != NULL) {
            char *sep = strchr(token, ':');
            if (sep) {
                *sep = '\0';
                if (strcasecmp(token, curso) == 0) {
                    // Substitui a nota
                    if (strlen(new_notas) > 0) strcat(new_notas, ",");
                    strcat(new_notas, nota_str);
                    substituido = 1;
                } else {
                    // Mantém a nota existente
                    *sep = ':';
                    if (strlen(new_notas) > 0) strcat(new_notas, ",");
                    strcat(new_notas, token);
                }
            }
            token = strtok_r(NULL, ",", &next_token);
        }
        
        if (!substituido) {
            // Adiciona a nova nota
            if (strlen(new_notas) > 0) strcat(new_notas, ",");
            strcat(new_notas, nota_str);
        }
        
        strncpy(u->notas, new_notas, sizeof(u->notas) - 1);
        u->notas[sizeof(u->notas) - 1] = '\0';
        free(new_notas);
    }
}

/* (Helper) Adiciona uma aula ao usuário */
void adicionar_aula_em_usuario(Usuario *u, const char *aula) {
    if (strlen(u->aulas) == 0) {
        strncpy(u->aulas, aula, sizeof(u->aulas) - 1);
    } else {
        if (strlen(u->aulas) + 1 + strlen(aula) < sizeof(u->aulas)) {
            strcat(u->aulas, ";");
            strcat(u->aulas, aula);
        }
    }
}

/* --- Funções de Leitura/Escrita de Arquivo --- */

/* Carrega todos os usuários do arquivo "usuarios.txt" para a memória */
/* (Usa parser manual para campos vazios ||) */
void carregar_usuarios() {
    liberar_usuarios_buffer(); // Libera antes de carregar
    usuarios = (Usuario*)malloc(sizeof(Usuario) * MAX_USERS);
    if (!usuarios) { printf("Erro de alocação de memória para usuários.\n"); return; }

    garantir_arquivo();
    FILE *f = fopen(ARQUIVO_USUARIOS, "r");
    if (!f) return;
    char linha[2048]; // Aumentado para suportar o novo campo feedback
    usuarios_count = 0; 
    
    while (fgets(linha, sizeof(linha), f)) {
        linha[strcspn(linha, "\n")] = 0;
        if (strlen(linha) == 0) continue;
        
        if (usuarios_count >= (size_t)MAX_USERS) {
            printf("Aviso: limite MAX_USERS atingido. Ignorando usuários adicionais no arquivo.\n");
            break;
        }
        
        Usuario u; memset(&u, 0, sizeof(Usuario));
        
        // Agora temos 9 campos: nome|email|senha_hash|tipo|cursos|notas|aulas|alunos|feedback
        char *parts[9] = {0};
        int idx = 0;
        char *current = linha; 

        for (idx = 0; idx < 9; idx++) {
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
        if (idx == 8 && part_count < 9) part_count = 9; 
        
        if (part_count >= 4) { 
            strncpy(u.nome, parts[0], sizeof(u.nome)-1);
            strncpy(u.email, parts[1], sizeof(u.email)-1);
            strncpy(u.senha_hash, parts[2], sizeof(u.senha_hash)-1);
            strncpy(u.tipo, parts[3], sizeof(u.tipo)-1);
            
            if (part_count > 4 && parts[4]) strncpy(u.cursos, parts[4], sizeof(u.cursos)-1);
            if (part_count > 5 && parts[5]) strncpy(u.notas, parts[5], sizeof(u.notas)-1);
            if (part_count > 6 && parts[6]) strncpy(u.aulas, parts[6], sizeof(u.aulas)-1);
            if (part_count > 7 && parts[7]) strncpy(u.alunos, parts[7], sizeof(u.alunos)-1);
            if (part_count > 8 && parts[8]) strncpy(u.feedback, parts[8], sizeof(u.feedback)-1); // NOVO CAMPO
            
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
        fprintf(f, "%s|%s|%s|%s|%s|%s|%s|%s|%s\n", // NOVO CAMPO %s
            u->nome, u->email, u->senha_hash, u->tipo,
            u->cursos[0] ? u->cursos : "",
            u->notas[0] ? u->notas : "",
            u->aulas[0] ? u->aulas : "",
            u->alunos[0] ? u->alunos : "",
            u->feedback[0] ? u->feedback : ""); // NOVO CAMPO
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
        return 0;
    }
    for (size_t i=0;i<MAX_TENTATIVAS_CAP;i++) tentativa_emails[i] = NULL;
    return 1;
}

/* (Login) Adiciona uma tentativa de login falha */
void adicionar_tentativa(const char *email) {
    int idx = index_tentativa(email);
    if (idx == -1) {
        if (tentativas_count >= MAX_TENTATIVAS_CAP) return; 
        idx = tentativas_count++;
        tentativa_emails[idx] = xstrdup(email);
        tentativa_cont[idx] = 0;
        tentativa_bloqueado[idx] = 0;
        tentativa_tempo[idx] = 0;
    }
    
    tentativa_cont[idx]++;
    if (tentativa_cont[idx] >= MAX_TENTATIVAS) {
        tentativa_bloqueado[idx] = 1;
        tentativa_tempo[idx] = time(NULL);
        printf("Conta bloqueada por %d segundos devido a muitas tentativas de login.\n", TEMPO_BLOQUEIO);
    }
}

/* (Login) Verifica se o email está bloqueado */
int esta_bloqueado(const char *email) {
    int idx = index_tentativa(email);
    if (idx == -1 || !tentativa_bloqueado[idx]) return 0;
    
    time_t agora = time(NULL);
    if (agora - tentativa_tempo[idx] >= TEMPO_BLOQUEIO) {
        tentativa_bloqueado[idx] = 0;
        tentativa_cont[idx] = 0;
        tentativa_tempo[idx] = 0;
        return 0;
    }
    return 1;
}

/* (Login) Limpa o contador de tentativas após login bem-sucedido */
void limpar_tentativas(const char *email) {
    int idx = index_tentativa(email);
    if (idx != -1) {
        tentativa_cont[idx] = 0;
        tentativa_bloqueado[idx] = 0;
        tentativa_tempo[idx] = 0;
    }
}

/* --- Funções de Cadastro e Login --- */

/* (Cadastro) Cadastra um novo usuário */
void cadastrar_usuario() {
    if (usuarios_count >= MAX_USERS) { printf("Limite de usuários atingido.\n"); return; }
    
    Usuario novo;
    char senha[65];
    char tipo_str[16];
    
    printf("=== Cadastro de Usuário ===\n");
    
    printf("Nome: "); if (!fgets(novo.nome, sizeof(novo.nome), stdin)) return; novo.nome[strcspn(novo.nome, "\n")] = 0; trim(novo.nome);
    
    printf("Email: "); if (!fgets(novo.email, sizeof(novo.email), stdin)) return; novo.email[strcspn(novo.email, "\n")] = 0; trim(novo.email);
    for (char *p=novo.email; *p; ++p) *p = tolower(*p);
    
    if (encontrar_usuario_por_email(novo.email)) { printf("Erro: Email já cadastrado.\n"); return; }
    
    printf("Senha: "); if (!fgets(senha, sizeof(senha), stdin)) return; senha[strcspn(senha, "\n")] = 0; trim(senha);
    if (strlen(senha) < 6) { printf("Erro: Senha muito curta (mínimo 6 caracteres).\n"); return; }
    
    printf("Tipo (aluno/professor): "); if (!fgets(tipo_str, sizeof(tipo_str), stdin)) return; tipo_str[strcspn(tipo_str, "\n")] = 0; trim(tipo_str);
    for (char *p=tipo_str; *p; ++p) *p = tolower(*p);
    
    if (strcmp(tipo_str, "aluno") != 0 && strcmp(tipo_str, "professor") != 0) { printf("Erro: Tipo de usuário inválido.\n"); return; }
    
    strncpy(novo.tipo, tipo_str, sizeof(novo.tipo)-1);
    sha256_string(senha, novo.senha_hash);
    
    // Inicializa campos de lista
    novo.cursos[0] = '\0';
    novo.notas[0] = '\0';
    novo.aulas[0] = '\0';
    novo.alunos[0] = '\0';
    novo.feedback[0] = '\0'; // NOVO CAMPO
    
    usuarios[usuarios_count++] = novo;
    salvar_usuarios();
    printf("Usuário cadastrado com sucesso!\n");
}

/* (Login) Tenta logar o usuário e retorna o índice no array de usuários ou -1 */
int login_usuario_index(char *out_email) {
    char email[128];
    char senha[65];
    char senha_hash[65];
    
    printf("=== Login ===\n");
    
    printf("Email: "); if (!fgets(email, sizeof(email), stdin)) return -1; email[strcspn(email, "\n")] = 0; trim(email);
    for (char *p=email; *p; ++p) *p = tolower(*p);
    
    if (esta_bloqueado(email)) {
        printf("Conta bloqueada. Tente novamente mais tarde.\n");
        return -1;
    }
    
    printf("Senha: "); if (!fgets(senha, sizeof(senha), stdin)) return -1; senha[strcspn(senha, "\n")] = 0; trim(senha);
    
    Usuario *u = encontrar_usuario_por_email(email);
    
    if (u) {
        sha256_string(senha, senha_hash);
        if (strcmp(u->senha_hash, senha_hash) == 0) {
            limpar_tentativas(email);
            strncpy(out_email, email, 127);
            printf("Login bem-sucedido!\n");
            return (int)(u - usuarios); // Retorna o índice
        }
    }
    
    adicionar_tentativa(email);
    printf("Email ou senha incorretos.\n");
    return -1;
}

/* --- Funções de IA (Inteligência Artificial) --- */

/* IA 3: Análise de Sentimento (Baseado em Léxico com Detecção de Negação)
 */

typedef struct {
    const char *palavra;
    int pontuacao;
} LexicoEntry;

// Dicionário expandido
static const LexicoEntry lexico[] = {
    // Positivos
    {"excelente", 4}, {"otimo", 4}, {"maravilhoso", 4}, {"perfeito", 4},
    {"bom", 3}, {"boa", 3}, {"gostei", 3}, {"adoro", 3}, {"amo", 3},
    {"legal", 2}, {"bacana", 2}, {"ajudou", 2}, {"claro", 2}, {"facil", 2},
    {"interessante", 2}, {"motivado", 2}, {"satisfeito", 2},
    // Negativos
    {"horrivel", -4}, {"pessimo", -4}, {"odio", -4}, {"detesto", -4},
    {"ruim", -3}, {"fraco", -3}, {"lento", -3}, {"chato", -3},
    {"dificil", -2}, {"confuso", -2}, {"travando", -2}, {"bug", -2},
    {"erro", -2}, {"problema", -2}, {"tedioso", -2}, {"triste", -2}
};
static const int lexico_size = sizeof(lexico) / sizeof(lexico[0]);

int analisar_sentimento(const char *texto) {
    if (!texto || strlen(texto) == 0) return 0;
    
    char tmp[1024]; 
    strncpy(tmp, texto, sizeof(tmp)-1); 
    tmp[sizeof(tmp)-1] = 0;
    
    // Converte tudo para minúsculas
    for (char *p = tmp; *p; ++p) *p = tolower(*p); 

    int pontuacao_total = 0;
    int inverter_proximo = 1; // 1 = normal, -1 = inverte o sentido

    // Tokeniza por espaço e pontuação básica
    // ATENÇÃO: Aqui usamos strtok porque analisar_sentimento pode ser chamado 
    // dentro de outro loop. O ideal seria usar strtok_r aqui também, mas 
    // vamos garantir que quem chama (menu_professor) use strtok_r no loop externo.
    char *token = strtok(tmp, " ,.!?;:\n");
    
    while (token != NULL) {
        // Verifica se é uma negação
        if (strcmp(token, "nao") == 0 || strcmp(token, "jamais") == 0 || strcmp(token, "nunca") == 0) {
            inverter_proximo = -1; // A próxima palavra terá valor invertido
        } else {
            int achou = 0;
            for (int i = 0; i < lexico_size; i++) {
                if (strcmp(token, lexico[i].palavra) == 0) {
                    pontuacao_total += (lexico[i].pontuacao * inverter_proximo);
                    achou = 1;
                    break;
                }
            }
            // Se achou uma palavra ou se a palavra é longa (não é um "de", "o", etc), reseta o inversor
            if (achou || strlen(token) > 2) { 
                inverter_proximo = 1; 
            }
        }
        token = strtok(NULL, " ,.!?;:\n");
    }
    
    return pontuacao_total;
}

// Função de Regressão Logística Simplificada para Risco

// Estrutura auxiliar para armazenar o par Curso:Nota
typedef struct {
    char curso[128];
    double nota;
} CursoNota;

// Função auxiliar para extrair todas as notas de um usuário em um array de CursoNota
int extrair_notas(const Usuario *u, CursoNota *lista_notas, int max_notas) {
    if (strlen(u->notas) == 0) return 0;
    
    char tmp[1024]; strncpy(tmp, u->notas, sizeof(tmp)-1); tmp[sizeof(tmp)-1] = 0;
    char *p = tmp;
    char *next_token;
    int count = 0;
    
    char *token = strtok_r(p, ",", &next_token);
    while (token != NULL && count < max_notas) {
        char *sep = strchr(token, ':');
        if (sep) {
            *sep = '\0';
            strncpy(lista_notas[count].curso, token, sizeof(lista_notas[count].curso) - 1);
            lista_notas[count].nota = atof(sep + 1);
            count++;
        }
        token = strtok_r(NULL, ",", &next_token);
    }
    return count;
}

// Função de Similaridade de Cosseno (Simplificada para vetores de notas)
double calcular_similaridade_cosseno(const Usuario *u1, const Usuario *u2) {
    CursoNota notas1[32]; int count1 = extrair_notas(u1, notas1, 32);
    CursoNota notas2[32]; int count2 = extrair_notas(u2, notas2, 32);
    
    if (count1 == 0 || count2 == 0) return 0.0;
    
    double produto_escalar = 0.0;
    double norma1_quadrada = 0.0;
    double norma2_quadrada = 0.0;
    
    // 1. Calcular o Produto Escalar (apenas para cursos em comum)
    for (int i = 0; i < count1; i++) {
        for (int j = 0; j < count2; j++) {
            if (strcasecmp(notas1[i].curso, notas2[j].curso) == 0) {
                produto_escalar += notas1[i].nota * notas2[j].nota;
            }
        }
    }
    
    // 2. Calcular a Norma Quadrada de cada vetor (todos os cursos)
    for (int i = 0; i < count1; i++) {
        norma1_quadrada += notas1[i].nota * notas1[i].nota;
    }
    for (int j = 0; j < count2; j++) {
        norma2_quadrada += notas2[j].nota * notas2[j].nota;
    }
    
    // 3. Calcular a Similaridade de Cosseno
    if (norma1_quadrada == 0.0 || norma2_quadrada == 0.0) return 0.0;
    
    return produto_escalar / (sqrt(norma1_quadrada) * sqrt(norma2_quadrada));
}

/* IA 2: Recomendação APRIMORADA (Similaridade + Popularidade) */

// Função auxiliar para contar popularidade de um curso
int contar_popularidade_curso(const char *nome_curso) {
    int count = 0;
    for (size_t i = 0; i < usuarios_count; i++) {
        if (email_na_lista(usuarios[i].cursos, nome_curso)) {
            count++;
        }
    }
    return count;
}

void recomendar_cursos(const Usuario *aluno) {
    double max_similaridade = -1.0;
    Usuario *aluno_similar = NULL;
    
    printf("Analisando perfil...\n");

    // 1. Tenta encontrar aluno similar (Existing Logic)
    for (size_t i = 0; i < usuarios_count; i++) {
        Usuario *outro = &usuarios[i];
        if (outro == aluno || strcmp(outro->tipo, "aluno") != 0) continue;
        
        double similaridade = calcular_similaridade_cosseno(aluno, outro);
        if (similaridade > max_similaridade) {
            max_similaridade = similaridade;
            aluno_similar = outro;
        }
    }
    
    char recomendacoes[1024] = ""; // Buffer para guardar recomendações únicas

    // ESTRATÉGIA A: Filtragem Colaborativa (Aluno Similar)
    if (aluno_similar != NULL && max_similaridade > 0.3) { // 0.3 é um limiar mínimo
        printf("> Encontrado perfil similar: %s (Match: %.0f%%)\n", aluno_similar->nome, max_similaridade*100);
        
        char cursos_similar[512]; 
        strncpy(cursos_similar, aluno_similar->cursos, sizeof(cursos_similar));
        char *curso = strtok(cursos_similar, ";");
        
        while (curso) {
            // Se o aluno atual NÃO tem o curso, recomenda
            if (!email_na_lista(aluno->cursos, curso)) {
                adicionar_email_na_lista(recomendacoes, sizeof(recomendacoes), curso);
            }
            curso = strtok(NULL, ";");
        }
    } else {
        printf("> Não encontramos um aluno com notas parecidas o suficiente.\n");
    }

    // ESTRATÉGIA B: Populares (Fallback - Se a estratégia A recomendou pouco ou nada)
    if (strlen(recomendacoes) == 0) {
        printf("> Buscando cursos mais populares na universidade...\n");
        
        // Varre todos os cursos de todos os usuários para achar candidatos
        for (size_t i = 0; i < usuarios_count; i++) {
            if (strcmp(usuarios[i].tipo, "aluno") != 0) continue;
            
            char temp_cursos[512];
            strncpy(temp_cursos, usuarios[i].cursos, sizeof(temp_cursos));
            char *c = strtok(temp_cursos, ";");
            
            while (c) {
                // Se o aluno ainda não tem o curso E ele ainda não está na lista de recomendação
                if (!email_na_lista(aluno->cursos, c) && !email_na_lista(recomendacoes, c)) {
                    // Critério simples: Se mais de 1 pessoa faz, recomenda
                    if (contar_popularidade_curso(c) >= 1) {
                         adicionar_email_na_lista(recomendacoes, sizeof(recomendacoes), c);
                    }
                }
                c = strtok(NULL, ";");
            }
            if (strlen(recomendacoes) > 200) break; // Limita para não encher demais
        }
    }

    // Exibir Resultados
    if (strlen(recomendacoes) > 0) {
        printf("\n=== Cursos Recomendados para Você ===\n");
        char temp_rec[1024];
        strncpy(temp_rec, recomendacoes, sizeof(temp_rec));
        char *r = strtok(temp_rec, ";");
        while (r) {
            printf("- %s\n", r);
            r = strtok(NULL, ";");
        }
    } else {
        printf("\nNenhuma recomendação disponível no momento.\n(Tente cadastrar mais alunos e cursos no sistema)\n");
    }
}

// Função de Regressão Logística Simplificada para Risco

/* IA 1: Previsão de Risco de Reprovação (Regressão Logística Simplificada)
  O risco é inversamente proporcional à média das notas.
 */

// Função auxiliar para calcular a média das notas de um aluno
double calcular_media_notas(const Usuario *u) {
    if (strlen(u->notas) == 0) return 0.0;
    
    char tmp[1024]; strncpy(tmp, u->notas, sizeof(tmp)-1); tmp[sizeof(tmp)-1] = 0;
    char *p = tmp;
    char *next_token;
    double soma_notas = 0.0;
    int count = 0;
    
    char *token = strtok_r(p, ",", &next_token);
    while (token != NULL) {
        char *sep = strchr(token, ':');
        if (sep) {
            double nota = atof(sep + 1);
            soma_notas += nota;
            count++;
        }
        token = strtok_r(NULL, ",", &next_token);
    }
    
    return count > 0 ? soma_notas / count : 0.0;
}

// Função de Regressão Logística Simplificada para Risco
// Mapeia a média das notas (0-10) para uma probabilidade de risco (0-100%)
// Quanto maior a nota, menor o risco.
double prever_risco_reprovacao(const Usuario *u) {
    double media = calcular_media_notas(u);
    
    // Parâmetros do modelo (ajustáveis):
    // O ideal é que a média 5.0 (metade) resulte em 50% de risco.
    // Usamos uma transformação linear para 'z' onde z = a * media + b
    // Se media=5, queremos z=0 (para sigmoid(0) = 0.5) -> 5a + b = 0 -> b = -5a
    // Se media=0, queremos alto risco (ex: 95%) -> sigmoid(z) = 0.05 -> z aprox -3
    // Se media=10, queremos baixo risco (ex: 5%) -> sigmoid(z) = 0.95 -> z aprox +3
    
    // Escolhendo a=0.6 e b=-3.0:
    // media=5 -> z = 0.6*5 - 3.0 = 0.0 -> Risco = 1 - 0.5 = 50%
    // media=0 -> z = -3.0 -> Risco = 1 - 0.047 = 95.3%
    // media=10 -> z = 3.0 -> Risco = 1 - 0.953 = 4.7%
    
    const double a = 0.6;
    const double b = -3.0;
    
    double z = a * media + b;
    
    // Função Sigmoide: P(sucesso) = 1 / (1 + e^-z)
    double probabilidade_sucesso = 1.0 / (1.0 + exp(-z));
    
    // Risco de Reprovação = 1 - P(sucesso)
    double risco = 1.0 - probabilidade_sucesso;
    
    return risco * 100.0; // Retorna em porcentagem
}

/* --- Funções de Menu --- */

/* Menu do Aluno */
void menu_aluno(const char *email_aluno) {
    char opcao[8];
    while (1) {
        carregar_usuarios(); 
        Usuario *aluno = encontrar_usuario_por_email(email_aluno);
        if (!aluno) { printf("Usuário não encontrado (ou foi removido). Saindo do menu.\n"); return; }

        printf("=== Menu Aluno ===\n1 - Ver minhas informações\n2 - Ver minhas notas\n3 - Receber Sugestões de Cursos (IA)\n4 - Deixar Feedback\n0 - Sair\nEscolha uma opção: ");
        if (!fgets(opcao, sizeof(opcao), stdin))
        break;
        trim(opcao);
        
        /* Opção 1: Ver informações */
        if (strcmp(opcao, "1") == 0) {
            printf("\nNome: %s\nEmail: %s\nCursos: %s\nAulas: %s\n\n", aluno->nome, aluno->email, strlen(aluno->cursos)? aluno->cursos : "Nenhum", 
            strlen(aluno->aulas)? aluno->aulas : "Nenhuma");
        }
        
        /* Opção 2: Ver notas */
        else if (strcmp(opcao, "2") == 0) {
            printf("\n=== Minhas Notas ===\n");
            if (strlen(aluno->notas)) { 
                char ntmp[1024]; strcpy(ntmp, aluno->notas); 
                char *p2 = strtok(ntmp, ","); 
                while (p2) { 
                    printf("  %s\n", p2); 
                    p2 = strtok(NULL, ","); 
                } 
            }
            else printf("  Nenhuma nota registrada.\n");
            printf("\n");
        }
        
        /* Opção 3: Receber Sugestões de Cursos (IA) - NOVO */
        else if (strcmp(opcao, "3") == 0) {
            printf("\n=== Recomendação de Cursos (IA) ===\n");
            recomendar_cursos(aluno);
            printf("\n");
        }
        
        /* Opção 4: Deixar Feedback - NOVO */
        else if (strcmp(opcao, "4") == 0) {
            printf("\n=== Deixar Feedback ===\n");
            printf("Digite seu feedback sobre o sistema ou um curso (máx. 1023 caracteres):\n");
            char feedback_input[1024];
            if (!fgets(feedback_input, sizeof(feedback_input), stdin)) continue;
            feedback_input[strcspn(feedback_input, "\n")] = 0;
            trim(feedback_input);
            
            strncpy(aluno->feedback, feedback_input, sizeof(aluno->feedback) - 1);
            salvar_usuarios();
            printf("Feedback registrado com sucesso!\n\n");
        }
        
        /* Opção 0: Sair do menu do aluno */
        else if (strcmp(opcao, "0") == 0) break; 
        
        /* Opção Inválida */
        else printf("Opção inválida.\n");
    }
}

/* Menu do Professor */
void menu_professor(const char *email_prof) {
    char opcao[8];
    while (1) {
        carregar_usuarios(); 
        Usuario *professor = encontrar_usuario_por_email(email_prof);
        if (!professor) { printf("Usuário não encontrado (ou foi removido). Saindo do menu.\n"); return; }

        printf("=== Menu Professor ===\n1 - Ver informações\n2 - Adicionar aluno\n3 - Adicionar curso para aluno\n4 - Adicionar nota para aluno\n5 - Adicionar aula para aluno\n6 - Ver alunos e dados\n7 - Previsão de Risco de Reprovação (IA)\n8 - Análise de Sentimento (IA)\n9 - Registrar Feedback para Aluno\n0 - Sair\nEscolha uma opção: ");
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
            } else printf("Aluno não encontrado ou não é um aluno.\n");
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
            if (!strlen(al->cursos)) { printf("Aluno não possui cursos. Adicione um curso primeiro.\n"); continue; }
            char tmp[512]; strcpy(tmp, al->cursos); char *lista[32]; int n=0; char *x = strtok(tmp, ";"); while (x && n<32) { lista[n++] = x; x = strtok(NULL, ";"); }
            
            for (int i=0;i<n;i++) {
                printf("%d - %s\n", i+1, lista[i]); 
            }
            
            char escolha[8]; printf("Escolha o número do curso para adicionar nota: "); if (!fgets(escolha, sizeof(escolha), stdin)) continue; trim(escolha); int idx = atoi(escolha); if (idx<1 || idx>n) { printf("Opção inválida.\n"); continue; }
            char nota_str[32]; printf("Digite a nota (0-10): "); if (!fgets(nota_str, sizeof(nota_str), stdin)) continue; nota_str[strcspn(nota_str, "\n")] = 0; trim(nota_str);
            double nota = atof(nota_str); if (nota < 0.0 || nota > 10.0) { printf("Nota inválida. Deve ser entre 0.0 e 10.0.\n"); continue; }
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
            
            // CORREÇÃO: Usar strtok_r para não conflitar com outros strtoks
            char *saveptr = NULL;
            char *t = strtok_r(tmp, ";", &saveptr);
            while (t) {
                Usuario *al = encontrar_usuario_por_email(t); 
                if (al) {
                    printf("\nAluno: %s - %s\n", al->nome, al->email);
                    printf("Cursos: %s\n", strlen(al->cursos)? al->cursos : "Nenhum");
                    printf("Notas:\n");
                    if (strlen(al->notas)) { char ntmp[1024]; strcpy(ntmp, al->notas); char *p2 = strtok(ntmp, ","); while (p2) { printf("  %s\n", p2); p2 = strtok(NULL, ","); } }
                    else printf("  Nenhuma nota.\n");
                    printf("Aulas: %s\n", strlen(al->aulas)? al->aulas : "Nenhuma");
                    printf("Feedback: %s\n", strlen(al->feedback)? al->feedback : "Nenhum");
                } else printf("Aluno %s não encontrado.\n", t);
                t = strtok_r(NULL, ";", &saveptr);
            }
            printf("\n");
        }
        
        /* Opção 7: Previsão de Risco de Reprovação (IA) - NOVO */
        else if (strcmp(opcao, "7") == 0) {
            if (strlen(professor->alunos) == 0) { printf("Você não tem alunos adicionados.\n\n"); continue; }
            printf("\n=== Previsão de Risco de Reprovação (IA) ===\n");
            char tmp[1024]; strncpy(tmp, professor->alunos, sizeof(tmp)-1); tmp[sizeof(tmp)-1]=0;
            
            // CORREÇÃO: Usar strtok_r
            char *saveptr = NULL;
            char *t = strtok_r(tmp, ";", &saveptr);
            while (t) {
                Usuario *al = encontrar_usuario_por_email(t); 
                if (al) {
                    double risco = prever_risco_reprovacao(al);
                    double media = calcular_media_notas(al);
                    printf("Aluno: %s (Média: %.2f) -> Risco de Reprovação: %.2f%%\n", al->nome, media, risco);
                }
                t = strtok_r(NULL, ";", &saveptr);
            }
            printf("\n");
        }
        
        /* Opção 8: Análise de Sentimento (IA) - NOVO */
        else if (strcmp(opcao, "8") == 0) {
            if (strlen(professor->alunos) == 0) { printf("Você não tem alunos adicionados.\n\n"); continue; }
            printf("\n=== Análise de Sentimento de Feedback (IA) ===\n");
            char tmp[1024]; strncpy(tmp, professor->alunos, sizeof(tmp)-1); tmp[sizeof(tmp)-1]=0;
            
            // CORREÇÃO: Usar strtok_r para evitar conflito com strtok interno da IA
            char *saveptr = NULL;
            char *t = strtok_r(tmp, ";", &saveptr);
            while (t) {
                Usuario *al = encontrar_usuario_por_email(t); 
                if (al && strlen(al->feedback) > 0) {
                    int sentimento = analisar_sentimento(al->feedback);
                    const char *sentimento_str = "Neutro";
                    if (sentimento > 0) sentimento_str = "Positivo";
                    else if (sentimento < 0) sentimento_str = "Negativo";
                    
                    printf("Aluno: %s -> Sentimento do Feedback: %s\n", al->nome, sentimento_str);
                    printf("   \"%s\"\n", al->feedback); // Mostra o texto original também
                } else if (al) {
                    printf("Aluno: %s -> Sem feedback registrado.\n", al->nome);
                }
                t = strtok_r(NULL, ";", &saveptr);
            }
            printf("\n");
        }
        
        /* Opção 9: Registrar Feedback para Aluno - NOVO */
        else if (strcmp(opcao, "9") == 0) {
            if (strlen(professor->alunos) == 0) { printf("Você não tem alunos adicionados.\n\n"); continue; }
            char email_aluno[128]; printf("Digite o email do aluno para registrar feedback: "); if (!fgets(email_aluno, sizeof(email_aluno), stdin)) continue; email_aluno[strcspn(email_aluno, "\n")] = 0; trim(email_aluno); for (char *p=email_aluno; *p; ++p) *p = tolower(*p);
            if (!email_na_lista(professor->alunos, email_aluno)) { printf("Aluno não está na sua lista.\n"); continue; }
            
            Usuario *al = encontrar_usuario_por_email(email_aluno); if (!al) { printf("Aluno não encontrado.\n"); continue; }
            
            printf("Digite o feedback para %s (máx. 1023 caracteres):\n", al->nome);
            char feedback_input[1024];
            if (!fgets(feedback_input, sizeof(feedback_input), stdin)) continue;
            feedback_input[strcspn(feedback_input, "\n")] = 0;
            trim(feedback_input);
            
            strncpy(al->feedback, feedback_input, sizeof(al->feedback) - 1);
            salvar_usuarios();
            printf("Feedback registrado para %s com sucesso!\n\n", al->nome);
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
    setlocale(LC_ALL, "portuguese"); 

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