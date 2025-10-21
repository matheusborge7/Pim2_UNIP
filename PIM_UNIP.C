# sistema_academico.py
import sqlite3
from datetime import datetime
from algoritmos import AlgoritmosAcademicos
from ia_sistema import IAProcessor

class SistemaAcademico:
    def _init_(self):
        self.conn = sqlite3.connect('academico.db', check_same_thread=False)
        self.cursor = self.conn.cursor()
        self.algoritmos = AlgoritmosAcademicos()
        self.ia_processor = IAProcessor()
        self.inicializar_banco_dados()
    
    def inicializar_banco_dados(self):
        """Inicializa todas as tabelas do sistema"""
        # Tabela de usuários
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS usuarios (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                tipo TEXT NOT NULL,
                nome TEXT NOT NULL,
                email TEXT
            )
        ''')
        
        # Tabela de turmas
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS turmas (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                nome TEXT NOT NULL,
                codigo TEXT UNIQUE,
                professor_id INTEGER,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (professor_id) REFERENCES usuarios (id)
            )
        ''')
        
        # Tabela de matrículas
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS matriculas (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                aluno_id INTEGER,
                turma_id INTEGER,
                data_matricula TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (aluno_id) REFERENCES usuarios (id),
                FOREIGN KEY (turma_id) REFERENCES turmas (id),
                UNIQUE(aluno_id, turma_id)
            )
        ''')
        
        # Tabela de atividades
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS atividades (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                titulo TEXT NOT NULL,
                descricao TEXT,
                data_criacao TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                data_entrega DATE,
                turma_id INTEGER,
                professor_id INTEGER,
                tipo TEXT DEFAULT 'tarefa',
                FOREIGN KEY (turma_id) REFERENCES turmas (id),
                FOREIGN KEY (professor_id) REFERENCES usuarios (id)
            )
        ''')
        
        # Tabela de entregas
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS entregas (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                atividade_id INTEGER,
                aluno_id INTEGER,
                resposta TEXT,
                arquivo_path TEXT,
                data_entrega TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                nota FLOAT,
                similaridade_detectada BOOLEAN DEFAULT FALSE,
                FOREIGN KEY (atividade_id) REFERENCES atividades (id),
                FOREIGN KEY (aluno_id) REFERENCES usuarios (id)
            )
        ''')
        
        # Tabela de aulas
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS aulas (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                turma_id INTEGER,
                data_aula DATE,
                conteudo TEXT,
                professor_id INTEGER,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (turma_id) REFERENCES turmas (id),
                FOREIGN KEY (professor_id) REFERENCES usuarios (id)
            )
        ''')
        
        # Inserir dados de exemplo
        self._inserir_dados_exemplo()
        self.conn.commit()
    
    def _inserir_dados_exemplo(self):
        """Insere dados de exemplo para testes"""
        # Usuários de exemplo
        usuarios_exemplo = [
            (1, 'admin', '1234', 'professor', 'Professor Admin', 'admin@escola.com'),
            (2, 'aluno1', '1234', 'aluno', 'João Silva', 'joao@escola.com'),
            (3, 'aluno2', '1234', 'aluno', 'Maria Santos', 'maria@escola.com'),
            (4, 'prof2', '1234', 'professor', 'Professora Ana', 'ana@escola.com')
        ]
        
        for usuario in usuarios_exemplo:
            self.cursor.execute('''
                INSERT OR IGNORE INTO usuarios (id, username, password, tipo, nome, email)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', usuario)
        
        # Turmas de exemplo
        turmas_exemplo = [
            (1, 'Programação Python', 'TURMA001', 1),
            (2, 'Banco de Dados', 'TURMA002', 4),
            (3, 'Redes de Computadores', 'TURMA003', 1)
        ]
        
        for turma in turmas_exemplo:
            self.cursor.execute('''
                INSERT OR IGNORE INTO turmas (id, nome, codigo, professor_id)
                VALUES (?, ?, ?, ?)
            ''', turma)
        
        # Matrículas de exemplo
        matriculas_exemplo = [
            (2, 1), (3, 1),  # Alunos na turma de Programação
            (2, 2), (3, 2),  # Alunos na turma de Banco de Dados
        ]
        
        for matricula in matriculas_exemplo:
            self.cursor.execute('''
                INSERT OR IGNORE INTO matriculas (aluno_id, turma_id)
                VALUES (?, ?)
            ''', matricula)
        
        # Atividades de exemplo
        atividades_exemplo = [
            (1, 'Lista de Exercícios 1', 'Resolva os exercícios sobre variáveis e loops', 
             '2024-12-15', 1, 1, 'tarefa'),
            (2, 'Projeto Banco de Dados', 'Crie um modelo ER para sistema acadêmico',
             '2024-12-20', 2, 4, 'projeto')
        ]
        
        for atividade in atividades_exemplo:
            self.cursor.execute('''
                INSERT OR IGNORE INTO atividades (id, titulo, descricao, data_entrega, turma_id, professor_id, tipo)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', atividade)
    
    # ========== MÉTODOS DE USUÁRIO ==========
    
    def autenticar_usuario(self, username, password):
        """Autentica usuário no sistema"""
        self.cursor.execute(
            "SELECT id, username, tipo, nome FROM usuarios WHERE username = ? AND password = ?",
            (username, password)
        )
        return self.cursor.fetchone()
    
    def obter_usuario_por_id(self, user_id):
        """Obtém dados do usuário por ID"""
        self.cursor.execute(
            "SELECT id, username, tipo, nome, email FROM usuarios WHERE id = ?",
            (user_id,)
        )
        return self.cursor.fetchone()
    
    # ========== MÉTODOS DE TURMAS ==========
    
    def listar_turmas(self, usuario_id=None, tipo_usuario=None):
        """Lista turmas do sistema"""
        if tipo_usuario == 'professor':
            self.cursor.execute('''
                SELECT t.id, t.nome, t.codigo, u.nome as professor_nome
                FROM turmas t
                LEFT JOIN usuarios u ON t.professor_id = u.id
                WHERE t.professor_id = ?
                ORDER BY t.nome
            ''', (usuario_id,))
        elif tipo_usuario == 'aluno':
            self.cursor.execute('''
                SELECT t.id, t.nome, t.codigo, u.nome as professor_nome
                FROM turmas t
                LEFT JOIN usuarios u ON t.professor_id = u.id
                JOIN matriculas m ON t.id = m.turma_id
                WHERE m.aluno_id = ?
                ORDER BY t.nome
            ''', (usuario_id,))
        else:
            self.cursor.execute('''
                SELECT t.id, t.nome, t.codigo, u.nome as professor_nome
                FROM turmas t
                LEFT JOIN usuarios u ON t.professor_id = u.id
                ORDER BY t.nome
            ''')
        
        return self.cursor.fetchall()
    
    def criar_turma(self, nome, codigo, professor_id):
        """Cria uma nova turma"""
        try:
            self.cursor.execute('''
                INSERT INTO turmas (nome, codigo, professor_id)
                VALUES (?, ?, ?)
            ''', (nome, codigo, professor_id))
            self.conn.commit()
            return True, "Turma criada com sucesso"
        except sqlite3.IntegrityError:
            return False, "Código da turma já existe"
    
    # ========== MÉTODOS DE ATIVIDADES ==========
    
    def listar_atividades(self, turma_id=None, usuario_id=None, tipo_usuario=None):
        """Lista atividades do sistema"""
        if turma_id:
            self.cursor.execute('''
                SELECT a.id, a.titulo, a.descricao, a.data_entrega, 
                       a.tipo, t.nome as turma_nome, u.nome as professor_nome
                FROM atividades a
                JOIN turmas t ON a.turma_id = t.id
                JOIN usuarios u ON a.professor_id = u.id
                WHERE a.turma_id = ?
                ORDER BY a.data_entrega
            ''', (turma_id,))
        elif tipo_usuario == 'aluno':
            self.cursor.execute('''
                SELECT a.id, a.titulo, a.descricao, a.data_entrega, 
                       a.tipo, t.nome as turma_nome, u.nome as professor_nome
                FROM atividades a
                JOIN turmas t ON a.turma_id = t.id
                JOIN usuarios u ON a.professor_id = u.id
                JOIN matriculas m ON t.id = m.turma_id
                WHERE m.aluno_id = ?
                ORDER BY a.data_entrega
            ''', (usuario_id,))
        else:
            self.cursor.execute('''
                SELECT a.id, a.titulo, a.descricao, a.data_entrega, 
                       a.tipo, t.nome as turma_nome, u.nome as professor_nome
                FROM atividades a
                JOIN turmas t ON a.turma_id = t.id
                JOIN usuarios u ON a.professor_id = u.id
                ORDER BY a.data_entrega
            ''')
        
        return self.cursor.fetchall()
    
    def criar_atividade(self, titulo, descricao, data_entrega, turma_id, professor_id, tipo='tarefa'):
        """Cria uma nova atividade"""
        try:
            self.cursor.execute('''
                INSERT INTO atividades (titulo, descricao, data_entrega, turma_id, professor_id, tipo)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (titulo, descricao, data_entrega, turma_id, professor_id, tipo))
            self.conn.commit()
            return True, "Atividade criada com sucesso"
        except Exception as e:
            return False, f"Erro ao criar atividade: {str(e)}"
    
    # ========== MÉTODOS DE ENTREGAS ==========
    
    def entregar_atividade(self, atividade_id, aluno_id, resposta, arquivo_path=None):
        """Registra entrega de atividade"""
        try:
            # Verificar similaridade com IA
            similaridade = self.ia_processor.verificar_similaridade(resposta)
            
            self.cursor.execute('''
                INSERT INTO entregas (atividade_id, aluno_id, resposta, arquivo_path, similaridade_detectada)
                VALUES (?, ?, ?, ?, ?)
            ''', (atividade_id, aluno_id, resposta, arquivo_path, similaridade))
            
            self.conn.commit()
            
            if similaridade:
                return True, "Atividade entregue (similaridade detectada - será analisada)"
            else:
                return True, "Atividade entregue com sucesso"
                
        except Exception as e:
            return False, f"Erro ao entregar atividade: {str(e)}"
    
    def listar_entregas(self, atividade_id=None, aluno_id=None):
        """Lista entregas de atividades"""
        if atividade_id and aluno_id:
            self.cursor.execute('''
                SELECT e.*, a.titulo, u.nome as aluno_nome
                FROM entregas e
                JOIN atividades a ON e.atividade_id = a.id
                JOIN usuarios u ON e.aluno_id = u.id
                WHERE e.atividade_id = ? AND e.aluno_id = ?
            ''', (atividade_id, aluno_id))
        elif atividade_id:
            self.cursor.execute('''
                SELECT e.*, a.titulo, u.nome as aluno_nome
                FROM entregas e
                JOIN atividades a ON e.atividade_id = a.id
                JOIN usuarios u ON e.aluno_id = u.id
                WHERE e.atividade_id = ?
            ''', (atividade_id,))
        else:
            self.cursor.execute('''
                SELECT e.*, a.titulo, u.nome as aluno_nome
                FROM entregas e
                JOIN atividades a ON e.atividade_id = a.id
                JOIN usuarios u ON e.aluno_id = u.id
            ''')
        
        return self.cursor.fetchall()
    
    # ========== MÉTODOS DE RELATÓRIOS ==========
    
    def gerar_relatorio_turma(self, turma_id):
        """Gera relatório completo da turma"""
        # Estatísticas da turma
        self.cursor.execute('''
            SELECT COUNT(*) as total_alunos
            FROM matriculas 
            WHERE turma_id = ?
        ''', (turma_id,))
        total_alunos = self.cursor.fetchone()[0]
        
        self.cursor.execute('''
            SELECT COUNT(*) as total_atividades
            FROM atividades 
            WHERE turma_id = ?
        ''', (turma_id,))
        total_atividades = self.cursor.fetchone()[0]
        
        self.cursor.execute('''
            SELECT COUNT(*) as entregas_pendentes
            FROM atividades a
            LEFT JOIN entregas e ON a.id = e.atividade_id
            WHERE a.turma_id = ? AND e.id IS NULL
        ''', (turma_id,))
        entregas_pendentes = self.cursor.fetchone()[0]
        
        return {
            'total_alunos': total_alunos,
            'total_atividades': total_atividades,
            'entregas_pendentes': entregas_pendentes,
            'sustentabilidade': f"Redução estimada de {total_atividades * 5} folhas de papel"
        }
    
    def fechar_conexao(self):
        """Fecha a conexão com o banco"""
        self.conn.close()