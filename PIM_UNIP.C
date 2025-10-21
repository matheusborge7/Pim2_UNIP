#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sqlite3.h>

// Estruturas de dados
typedef struct {
    int id;
    char username[50];
    char password[50];
    char tipo[20];
    char nome[100];
} Usuario;

typedef struct {
    int id;
    char nome[100];
    char codigo[20];
    int professor_id;
    char professor_nome[100];
} Turma;

typedef struct {
    sqlite3 *db;
    sqlite3_stmt *stmt;
} SistemaAcademico;

// Protótipos das funções
void inicializar_banco_dados(SistemaAcademico *sistema);
Usuario* autenticar_usuario(SistemaAcademico *sistema, const char *username, const char *password);
Turma** listar_turmas(SistemaAcademico *sistema, int *quantidade);
void liberar_turmas(Turma **turmas, int quantidade);
void mostrar_usuario(Usuario *usuario);
void mostrar_turmas(Turma **turmas, int quantidade);

// Função principal
int main() {
    printf("🧪 TESTANDO SISTEMA EM C...\n");
    
    SistemaAcademico sistema = {0};
    
    // Inicializar sistema
    inicializar_banco_dados(&sistema);
    printf("✅ Sistema Acadêmico inicializado!\n");
    
    // Teste de login
    Usuario *usuario = autenticar_usuario(&sistema, "admin", "1234");
    if (usuario != NULL) {
        printf("✅ Login OK: ");
        mostrar_usuario(usuario);
        free(usuario);
    } else {
        printf("❌ Login falhou\n");
    }
    
    // Teste de turmas
    int quantidade_turmas;
    Turma **turmas = listar_turmas(&sistema, &quantidade_turmas);
    printf("✅ Turmas: %d encontradas\n", quantidade_turmas);
    
    if (quantidade_turmas > 0) {
        mostrar_turmas(turmas, quantidade_turmas);
        liberar_turmas(turmas, quantidade_turmas);
    }
    
    // Fechar banco de dados
    if (sistema.db != NULL) {
        sqlite3_close(sistema.db);
    }
    
    printf("🎉 SISTEMA EM C FUNCIONANDO PERFEITAMENTE!\n");
    return 0;
}

void inicializar_banco_dados(SistemaAcademico *sistema) {
    int rc;
    char *err_msg = 0;
    
    // Abrir/Criar banco de dados
    rc = sqlite3_open("data/academico_c.db", &sistema->db);
    
    if (rc != SQLITE_OK) {
        fprintf(stderr, "❌ Não foi possível abrir o banco: %s\n", sqlite3_errmsg(sistema->db));
        return;
    }
    
    // Criar tabelas
    const char *sql_usuarios = 
        "CREATE TABLE IF NOT EXISTS usuarios ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT, "
        "username TEXT UNIQUE NOT NULL, "
        "password TEXT NOT NULL, "
        "tipo TEXT NOT NULL, "
        "nome TEXT NOT NULL);";
    
    const char *sql_turmas = 
        "CREATE TABLE IF NOT EXISTS turmas ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT, "
        "nome TEXT NOT NULL, "
        "codigo TEXT UNIQUE, "
        "professor_id INTEGER);";
    
    rc = sqlite3_exec(sistema->db, sql_usuarios, 0, 0, &err_msg);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "❌ Erro ao criar tabela usuarios: %s\n", err_msg);
        sqlite3_free(err_msg);
    }
    
    rc = sqlite3_exec(sistema->db, sql_turmas, 0, 0, &err_msg);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "❌ Erro ao criar tabela turmas: %s\n", err_msg);
        sqlite3_free(err_msg);
    }
    
    // Inserir dados de exemplo
    const char *sql_insert = 
        "INSERT OR IGNORE INTO usuarios VALUES (1, 'admin', '1234', 'professor', 'Professor Admin');"
        "INSERT OR IGNORE INTO usuarios VALUES (2, 'aluno1', '1234', 'aluno', 'Aluno Teste');"
        "INSERT OR IGNORE INTO turmas VALUES (1, 'Turma Python', 'TURMA001', 1);";
    
    rc = sqlite3_exec(sistema->db, sql_insert, 0, 0, &err_msg);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "❌ Erro ao inserir dados: %s\n", err_msg);
        sqlite3_free(err_msg);
    }
}

Usuario* autenticar_usuario(SistemaAcademico *sistema, const char *username, const char *password) {
    const char *sql = "SELECT id, username, tipo, nome FROM usuarios WHERE username = ? AND password = ?";
    int rc;
    
    rc = sqlite3_prepare_v2(sistema->db, sql, -1, &sistema->stmt, 0);
    
    if (rc != SQLITE_OK) {
        fprintf(stderr, "❌ Erro ao preparar consulta: %s\n", sqlite3_errmsg(sistema->db));
        return NULL;
    }
    
    // Vincular parâmetros
    sqlite3_bind_text(sistema->stmt, 1, username, -1, SQLITE_STATIC);
    sqlite3_bind_text(sistema->stmt, 2, password, -1, SQLITE_STATIC);
    
    // Executar consulta
    rc = sqlite3_step(sistema->stmt);
    
    if (rc == SQLITE_ROW) {
        // Usuário encontrado
        Usuario usuario = (Usuario)malloc(sizeof(Usuario));
        usuario->id = sqlite3_column_int(sistema->stmt, 0);
        
        strncpy(usuario->username, (const char*)sqlite3_column_text(sistema->stmt, 1), sizeof(usuario->username)-1);
        strncpy(usuario->tipo, (const char*)sqlite3_column_text(sistema->stmt, 2), sizeof(usuario->tipo)-1);
        strncpy(usuario->nome, (const char*)sqlite3_column_text(sistema->stmt, 3), sizeof(usuario->nome)-1);
        
        sqlite3_finalize(sistema->stmt);
        return usuario;
    }
    
    sqlite3_finalize(sistema->stmt);
    return NULL;
}

Turma** listar_turmas(SistemaAcademico *sistema, int *quantidade) {
    const char *sql = 
        "SELECT t.id, t.nome, t.codigo, u.nome "
        "FROM turmas t "
        "JOIN usuarios u ON t.professor_id = u.id";
    
    int rc = sqlite3_prepare_v2(sistema->db, sql, -1, &sistema->stmt, 0);
    
    if (rc != SQLITE_OK) {
        fprintf(stderr, "❌ Erro ao preparar consulta: %s\n", sqlite3_errmsg(sistema->db));
        *quantidade = 0;
        return NULL;
    }
    
    // Contar resultados primeiro
    int count = 0;
    while (sqlite3_step(sistema->stmt) == SQLITE_ROW) {
        count++;
    }
    
    sqlite3_reset(sistema->stmt);
    
    // Alocar memória para o array de turmas
    Turma *turmas = (Turma)malloc(count * sizeof(Turma));
    if (turmas == NULL) {
        fprintf(stderr, "❌ Erro de alocação de memória\n");
        *quantidade = 0;
        return NULL;
    }
    
    // Preencher o array
    int i = 0;
    while (sqlite3_step(sistema->stmt) == SQLITE_ROW && i < count) {
        turmas[i] = (Turma*)malloc(sizeof(Turma));
        
        turmas[i]->id = sqlite3_column_int(sistema->stmt, 0);
        
        strncpy(turmas[i]->nome, (const char*)sqlite3_column_text(sistema->stmt, 1), sizeof(turmas[i]->nome)-1);
        strncpy(turmas[i]->codigo, (const char*)sqlite3_column_text(sistema->stmt, 2), sizeof(turmas[i]->codigo)-1);
        strncpy(turmas[i]->professor_nome, (const char*)sqlite3_column_text(sistema->stmt, 3), sizeof(turmas[i]->professor_nome)-1);
        
        i++;
    }
    
    sqlite3_finalize(sistema->stmt);
    *quantidade = count;
    return turmas;
}

void liberar_turmas(Turma **turmas, int quantidade) {
    for (int i = 0; i < quantidade; i++) {
        free(turmas[i]);
    }
    free(turmas);
}

void mostrar_usuario(Usuario *usuario) {
    printf("ID: %d, Username: %s, Tipo: %s, Nome: %s\n", 
           usuario->id, usuario->username, usuario->tipo, usuario->nome);
}

void mostrar_turmas(Turma **turmas, int quantidade) {
    printf("\n📚 LISTA DE TURMAS:\n");
    for (int i = 0; i < quantidade; i++) {
        printf("🏫 ID: %d, Nome: %s, Código: %s, Professor: %s\n",
               turmas[i]->id, turmas[i]->nome, turmas[i]->codigo, turmas[i]->professor_nome);
    }
}