// server.js

// 1. Importação de Módulos
const express = require('express');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const axios = require('axios');
const sqlite3 = require('sqlite3').verbose();

// 2. Configuração Inicial
const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'seu-segredo-super-secreto-padrao';
const DB_FILE = path.join(__dirname, 'darkscript.db');

// Middlewares
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// 3. Conexão com o Banco de Dados SQLite
const db = new sqlite3.Database(DB_FILE, (err) => {
    if (err) {
        console.error('Erro ao conectar ao SQLite:', err.message);
    } else {
        console.log('Conectado ao banco de dados SQLite.');
        initializeDb();
    }
});

// Função de inicialização da base de dados
const initializeDb = async () => {
    db.serialize(() => {
        db.run(`
          CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            settings TEXT,
            role TEXT NOT NULL DEFAULT 'user',
            is_active INTEGER NOT NULL DEFAULT 0,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            last_login_at DATETIME
          );
        `);
        // Adicionar a coluna last_login_at se ela não existir, para compatibilidade com bancos de dados antigos
        db.run("ALTER TABLE users ADD COLUMN last_login_at DATETIME", () => {});

        db.run(`
            CREATE TABLE IF NOT EXISTS app_status (
                key TEXT PRIMARY KEY,
                value TEXT
            );
        `);
        console.log("Tabelas verificadas/criadas com sucesso.");

        const adminEmail = 'rudysilvaads@gmail.com';
        const adminPassword = '253031';

        db.get("SELECT id FROM users WHERE email = ?", [adminEmail], (err, row) => {
            if (err) {
                console.error("Erro ao verificar admin:", err.message);
                return;
            }
            bcrypt.genSalt(10, (err, salt) => {
                bcrypt.hash(adminPassword, salt, (err, hash) => {
                    if (row) {
                        db.run("UPDATE users SET role = 'admin', is_active = 1 WHERE email = ?", [adminEmail]);
                        console.log(`Cargo de administrador e status ativo para ${adminEmail} verificado e garantido.`);
                    } else {
                        db.run(
                            "INSERT INTO users (email, password_hash, role, is_active, settings) VALUES (?, ?, 'admin', 1, '{}')",
                            [adminEmail, hash]
                        );
                        console.log(`Utilizador administrador ${adminEmail} criado com sucesso.`);
                    }
                });
            });
        });
    });
};

// 4. Middlewares de Segurança
const verifyToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ message: 'Acesso negado. Nenhum token fornecido.' });
    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err) return res.status(403).json({ message: 'Token inválido ou expirado.' });
        req.user = decoded;
        next();
    });
};

const requireAdmin = (req, res, next) => {
    if (req.user.role !== 'admin') return res.status(403).json({ message: 'Acesso negado. Recurso exclusivo para administradores.' });
    next();
};

// 5. Rotas da API
app.post('/api/register', (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ message: 'E-mail e senha são obrigatórios.' });
    
    bcrypt.genSalt(10, (err, salt) => {
        bcrypt.hash(password, salt, (err, hash) => {
            if (err) return res.status(500).json({ message: 'Erro ao criar hash da senha.' });
            db.run(
                'INSERT INTO users (email, password_hash, settings, is_active) VALUES (?, ?, ?, 0)',
                [email, hash, '{}'],
                function (err) {
                    if (err) {
                        if (err.message.includes('UNIQUE constraint failed')) {
                            return res.status(409).json({ message: 'Este e-mail já está em uso.' });
                        }
                        return res.status(500).json({ message: 'Erro interno do servidor.' });
                    }
                    res.status(201).json({ id: this.lastID, email });
                }
            );
        });
    });
});

app.post('/api/login', (req, res) => {
    const { email, password, rememberMe } = req.body;
    if (!email || !password) return res.status(400).json({ message: 'E-mail e senha são obrigatórios.' });

    db.get('SELECT * FROM users WHERE email = ?', [email], (err, user) => {
        if (err || !user) {
            return res.status(401).json({ message: 'Email ou senha inválidos.' });
        }
        bcrypt.compare(password, user.password_hash, (err, isMatch) => {
            if (err || !isMatch) {
                return res.status(401).json({ message: 'Email ou senha inválidos.' });
            }
            if (!user.is_active) {
                return res.status(403).json({ message: 'A sua conta precisa de ser ativada por um administrador.' });
            }

            db.run("UPDATE users SET last_login_at = CURRENT_TIMESTAMP WHERE id = ?", [user.id], (updateErr) => {
                if(updateErr) console.error("Error updating last login:", updateErr.message);
            });

            const expiresIn = rememberMe ? '30d' : '24h';
            const token = jwt.sign({ id: user.id, role: user.role }, JWT_SECRET, { expiresIn });
            res.json({ 
                message: 'Login bem-sucedido!', 
                token,
                user: { id: user.id, email: user.email, role: user.role }
            });
        });
    });
});

app.get('/api/verify-session', verifyToken, (req, res) => {
    db.get('SELECT id, email, role FROM users WHERE id = ?', [req.user.id], (err, user) => {
        if (err || !user) return res.status(404).json({ message: 'Utilizador não encontrado.' });
        res.json({ user });
    });
});

app.get('/api/settings', verifyToken, (req, res) => {
    db.get('SELECT settings FROM users WHERE id = ?', [req.user.id], (err, row) => {
        if (err) return res.status(500).json({ message: 'Erro interno do servidor.' });
        res.json(row && row.settings ? JSON.parse(row.settings) : {});
    });
});

app.post('/api/settings', verifyToken, (req, res) => {
    const { settings } = req.body;
    db.run('UPDATE users SET settings = ? WHERE id = ?', [JSON.stringify(settings), req.user.id], (err) => {
        if (err) return res.status(500).json({ message: 'Erro interno do servidor.' });
        res.json({ message: 'Configurações salvas com sucesso!' });
    });
});

app.get('/api/status', (req, res) => { 
    db.all("SELECT key, value FROM app_status WHERE key IN ('maintenance', 'announcement')", (err, rows) => {
        if (err) return res.status(500).json({ message: 'Erro interno do servidor.' });
        const status = {
            maintenance: JSON.parse(rows.find(r => r.key === 'maintenance')?.value || '{ "is_on": false, "message": "" }'),
            announcement: JSON.parse(rows.find(r => r.key === 'announcement')?.value || 'null')
        };
        res.json(status);
    });
});

// 6. Rota de IA com Fallback
app.post('/api/generate', verifyToken, (req, res) => {
    const { prompt, schema } = req.body;
    if (!prompt) return res.status(400).json({ message: "O prompt é obrigatório." });

    db.get('SELECT settings FROM users WHERE id = ?', [req.user.id], async (err, row) => {
        if (err || !row) return res.status(404).json({ message: 'Utilizador não encontrado.' });
        
        const settings = row.settings ? JSON.parse(row.settings) : {};
        const openAIKey = settings.openai;
        const geminiKeys = (Array.isArray(settings.gemini) ? settings.gemini : [settings.gemini]).filter(k => k && k.trim() !== '');

        let lastError = null;

        if (openAIKey) {
            try {
                const response = await axios.post('https://api.openai.com/v1/chat/completions', 
                    { model: "gpt-3.5-turbo", messages: [{ role: "user", content: prompt }], ...(schema && { response_format: { type: "json_object" } }) },
                    { headers: { 'Authorization': `Bearer ${openAIKey}` }, timeout: 90000 }
                );
                const content = response.data.choices[0].message.content;
                return res.json({ data: schema ? JSON.parse(content) : { text: content }, apiSource: 'OpenAI', backupUsed: false });
            } catch (error) {
                lastError = error;
                console.error("Erro OpenAI, tentando Gemini:", error.message);
            }
        }

        if (geminiKeys.length > 0) {
            for (let i = 0; i < geminiKeys.length; i++) {
                const key = geminiKeys[i];
                if (!key) continue;
                try {
                    const apiUrl = `https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash-latest:generateContent?key=${key}`;
                    let payload = { contents: [{ role: "user", parts: [{ text: prompt }] }] };
                    if (schema) payload.generationConfig = { response_mime_type: "application/json", response_schema: schema };
                    
                    const response = await axios.post(apiUrl, payload, { headers: { 'Content-Type': 'application/json' }, timeout: 90000 });
                    
                    if (response.data.candidates?.[0]?.content?.parts?.[0]) {
                        const text = response.data.candidates[0].content.parts[0].text;
                        return res.json({ 
                            data: schema ? JSON.parse(text) : { text }, 
                            apiSource: 'Gemini', 
                            backupUsed: i > 0 
                        });
                    }
                } catch (error) {
                    lastError = error;
                    console.error(`Falha com chave Gemini #${i + 1}, tentando próxima:`, error.message);
                }
            }
        }
        
        let errorMessage = "Nenhuma API de IA disponível ou todas falharam.";
        if (lastError) {
            const apiError = lastError.response?.data?.error?.message || lastError.message;
            if (apiError.toLowerCase().includes('quota') || apiError.toLowerCase().includes('billing') || apiError.toLowerCase().includes('api key not valid')) {
                errorMessage = "Todas as chaves de API falharam, possivelmente por falta de créditos/tokens ou chave inválida. Verifique suas configurações.";
            } else {
                 errorMessage = `Falha ao gerar conteúdo: ${apiError}`;
            }
        }
       
        return res.status(500).json({ message: errorMessage });
    });
});


// 7. Rotas de Administração
app.get('/api/admin/users', verifyToken, requireAdmin, (req, res) => {
    const { status = 'active', page = 1, limit = 10 } = req.query;
    const isActive = status === 'active' ? 1 : 0;
    const offset = (parseInt(page) - 1) * parseInt(limit);

    const countQuery = `SELECT COUNT(*) as count FROM users WHERE is_active = ?`;
    const dataQuery = `SELECT id, email, role, is_active, created_at, last_login_at FROM users WHERE is_active = ? ORDER BY created_at DESC LIMIT ? OFFSET ?`;

    db.get(countQuery, [isActive], (err, row) => {
        if (err) return res.status(500).json({ message: "Erro ao contar utilizadores." });
        
        const totalUsers = row.count;
        const totalPages = Math.ceil(totalUsers / parseInt(limit));

        db.all(dataQuery, [isActive, parseInt(limit), offset], (err, rows) => {
            if (err) return res.status(500).json({ message: "Erro ao buscar utilizadores." });

            res.json({
                data: rows,
                totalPages: totalPages,
                currentPage: parseInt(page),
                total: totalUsers
            });
        });
    });
});

app.put('/api/admin/user/:userId/status', verifyToken, requireAdmin, (req, res) => {
    const { userId } = req.params;
    const { isActive } = req.body;
    db.run('UPDATE users SET is_active = ? WHERE id = ?', [isActive ? 1 : 0, userId], (err) => {
        if (err) return res.status(500).json({ message: "Erro interno do servidor." });
        res.json({ message: 'Status do utilizador atualizado com sucesso.' });
    });
});

app.put('/api/admin/user/:userId/role', verifyToken, requireAdmin, (req, res) => {
    const { userId } = req.params;
    const { role } = req.body;

    if (!role || (role !== 'admin' && role !== 'user')) {
        return res.status(400).json({ message: 'Cargo fornecido é inválido.' });
    }

    if (userId === '1' || userId === req.user.id.toString()) {
        return res.status(403).json({ message: 'O cargo deste utilizador não pode ser alterado.' });
    }

    db.run('UPDATE users SET role = ? WHERE id = ?', [role, userId], function (err) {
        if (err) {
            return res.status(500).json({ message: "Erro interno do servidor ao atualizar o cargo." });
        }
        if (this.changes === 0) {
            return res.status(404).json({ message: "Utilizador não encontrado." });
        }
        res.json({ message: 'Cargo do utilizador atualizado com sucesso.' });
    });
});

app.post('/api/admin/approve-all', verifyToken, requireAdmin, (req, res) => {
    db.run("UPDATE users SET is_active = 1 WHERE is_active = 0", function(err) {
        if (err) return res.status(500).json({ message: "Erro interno do servidor." });
        res.json({ message: `${this.changes} utilizador(es) pendente(s) foram aprovados.` });
    });
});

app.delete('/api/admin/user/:userId', verifyToken, requireAdmin, (req, res) => {
    const { userId } = req.params;
    if (userId === '1' || userId === req.user.id.toString()) {
        return res.status(403).json({ message: 'Este utilizador não pode ser excluído.' });
    }
    db.run('DELETE FROM users WHERE id = ?', [userId], (err) => {
        if (err) return res.status(500).json({ message: "Erro interno do servidor." });
        res.json({ message: 'Utilizador excluído com sucesso.' });
    });
});

app.get('/api/admin/stats', verifyToken, requireAdmin, (req, res) => {
    db.get("SELECT COUNT(*) as totalUsers FROM users", [], (err, total) => {
        if (err) return res.status(500).json({ message: 'Erro interno.'});
        db.get("SELECT COUNT(*) as pendingActivation FROM users WHERE is_active = 0", [], (err, pending) => {
            if (err) return res.status(500).json({ message: 'Erro interno.'});
            res.json({
                totalUsers: total.totalUsers,
                pendingActivation: pending.pendingActivation,
                onlineNow: 0, // Placeholder
                loginsLast24h: 0 // Placeholder
            });
        });
    });
});

app.post('/api/admin/maintenance', verifyToken, requireAdmin, (req, res) => {
    const { is_on, message } = req.body;
    const value = JSON.stringify({ is_on, message });
    db.run("REPLACE INTO app_status (key, value) VALUES ('maintenance', ?)", [value], (err) => {
        if (err) return res.status(500).json({ message: "Erro ao atualizar o modo de manutenção." });
        res.json({ message: 'Modo de manutenção atualizado com sucesso.' });
    });
});

app.post('/api/admin/announcement', verifyToken, requireAdmin, (req, res) => {
    const { message } = req.body;
    const value = JSON.stringify({ message });
     db.run("REPLACE INTO app_status (key, value) VALUES ('announcement', ?)", [value], (err) => {
        if (err) return res.status(500).json({ message: "Erro ao atualizar o anúncio." });
        res.json({ message: 'Anúncio global atualizado com sucesso.' });
    });
});


// 8. Rota Genérica
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// 9. Inicialização
app.listen(PORT, () => {
  console.log(`Servidor rodando na porta ${PORT}`);
});

// Graceful shutdown
process.on('SIGINT', () => {
    db.close((err) => {
        if (err) console.error(err.message);
        console.log('Conexão com o banco de dados fechada.');
        process.exit(0);
    });
});

