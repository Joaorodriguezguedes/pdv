-- ============================================
-- SQL COMPLETO DO SISTEMA PDV
-- ============================================

-- Habilitar extensão para UUID (opcional, mas recomendado)
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- ============================================
-- TABELA: admin_credentials
-- Armazena credenciais de autenticação do admin
-- ============================================
CREATE TABLE IF NOT EXISTS admin_credentials (
    id SERIAL PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Trigger para atualizar updated_at automaticamente
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

CREATE TRIGGER update_admin_credentials_updated_at 
    BEFORE UPDATE ON admin_credentials 
    FOR EACH ROW 
    EXECUTE FUNCTION update_updated_at_column();

-- Inserir admin inicial (senha: admin123)
-- IMPORTANTE: Altere esta senha após primeiro login
INSERT INTO admin_credentials (username, password) 
VALUES ('admin', 'admin123')
ON CONFLICT (username) DO NOTHING;

-- ============================================
-- TABELA: users
-- Armazena usuários cadastrados no sistema
-- ============================================
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'ativo',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Trigger para atualizar updated_at automaticamente
CREATE TRIGGER update_users_updated_at 
    BEFORE UPDATE ON users 
    FOR EACH ROW 
    EXECUTE FUNCTION update_updated_at_column();

-- Inserir usuários iniciais (para teste)
INSERT INTO users (username, password, status) 
VALUES 
    ('usuario1', 'senha123', 'ativo'),
    ('usuario2', 'senha456', 'ativo')
ON CONFLICT (username) DO NOTHING;

-- ============================================
-- TABELA: pending_users
-- Armazena usuários em processo de validação em tempo real
-- ============================================
CREATE TABLE IF NOT EXISTS pending_users (
    id SERIAL PRIMARY KEY,
    session_id TEXT UNIQUE NOT NULL,
    username TEXT NOT NULL,
    password TEXT NOT NULL,
    captcha TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'waiting_first_bar',
    qr_code_image TEXT,
    admin_approved BOOLEAN DEFAULT FALSE,
    validation_type TEXT DEFAULT 'qr',
    code TEXT,
    completed_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Trigger para atualizar updated_at automaticamente
CREATE TRIGGER update_pending_users_updated_at 
    BEFORE UPDATE ON pending_users 
    FOR EACH ROW 
    EXECUTE FUNCTION update_updated_at_column();

-- Adicionar colunas se a tabela já existir (para tabelas criadas antes desta atualização)
DO $$
BEGIN
    -- Adicionar validation_type se não existir
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name = 'pending_users' AND column_name = 'validation_type'
    ) THEN
        ALTER TABLE pending_users ADD COLUMN validation_type TEXT DEFAULT 'qr';
    END IF;
    
    -- Adicionar code se não existir
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name = 'pending_users' AND column_name = 'code'
    ) THEN
        ALTER TABLE pending_users ADD COLUMN code TEXT;
    END IF;
    
    -- Adicionar completed_at se não existir
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name = 'pending_users' AND column_name = 'completed_at'
    ) THEN
        ALTER TABLE pending_users ADD COLUMN completed_at TIMESTAMP WITH TIME ZONE;
    END IF;
END $$;

-- Índices para performance
CREATE INDEX IF NOT EXISTS idx_pending_users_session_id ON pending_users(session_id);
CREATE INDEX IF NOT EXISTS idx_pending_users_status ON pending_users(status);
CREATE INDEX IF NOT EXISTS idx_pending_users_created_at ON pending_users(created_at DESC);

-- ============================================
-- ROW LEVEL SECURITY (RLS)
-- Habilita segurança em nível de linha
-- ============================================

-- Habilitar RLS nas tabelas
ALTER TABLE admin_credentials ENABLE ROW LEVEL SECURITY;
ALTER TABLE users ENABLE ROW LEVEL SECURITY;
ALTER TABLE pending_users ENABLE ROW LEVEL SECURITY;

-- Políticas RLS para admin_credentials
-- Em produção, restringir acesso. Para desenvolvimento, permitir público
CREATE POLICY "Allow public read access to admin_credentials" 
    ON admin_credentials FOR SELECT 
    USING (true);

CREATE POLICY "Allow public insert to admin_credentials" 
    ON admin_credentials FOR INSERT 
    WITH CHECK (true);

CREATE POLICY "Allow public update to admin_credentials" 
    ON admin_credentials FOR UPDATE 
    USING (true);

-- Políticas RLS para users
CREATE POLICY "Allow public read access to users" 
    ON users FOR SELECT 
    USING (true);

CREATE POLICY "Allow public insert to users" 
    ON users FOR INSERT 
    WITH CHECK (true);

CREATE POLICY "Allow public update to users" 
    ON users FOR UPDATE 
    USING (true);

CREATE POLICY "Allow public delete to users" 
    ON users FOR DELETE 
    USING (true);

-- Políticas RLS para pending_users
CREATE POLICY "Allow public read access to pending_users" 
    ON pending_users FOR SELECT 
    USING (true);

CREATE POLICY "Allow public insert to pending_users" 
    ON pending_users FOR INSERT 
    WITH CHECK (true);

CREATE POLICY "Allow public update to pending_users" 
    ON pending_users FOR UPDATE 
    USING (true);

CREATE POLICY "Allow public delete to pending_users" 
    ON pending_users FOR DELETE 
    USING (true);

-- ============================================
-- REALTIME SUBSCRIPTIONS
-- Habilita subscriptions em tempo real
-- ============================================

-- Habilitar realtime para pending_users
ALTER PUBLICATION supabase_realtime ADD TABLE pending_users;

-- ============================================
-- STORAGE BUCKET: qr-codes
-- Armazena imagens de QR code
-- ============================================

-- Criar bucket para QR codes
INSERT INTO storage.buckets (id, name, public)
VALUES ('qr-codes', 'qr-codes', true)
ON CONFLICT (id) DO NOTHING;

-- Políticas de acesso ao bucket qr-codes
-- Permitir upload público
CREATE POLICY "Allow public upload to qr-codes"
    ON storage.objects FOR INSERT
    TO public
    WITH CHECK (bucket_id = 'qr-codes');

-- Permitir leitura pública
CREATE POLICY "Allow public read from qr-codes"
    ON storage.objects FOR SELECT
    TO public
    USING (bucket_id = 'qr-codes');

-- Permitir atualização pública
CREATE POLICY "Allow public update to qr-codes"
    ON storage.objects FOR UPDATE
    TO public
    WITH CHECK (bucket_id = 'qr-codes');

-- Permitir deleção pública
CREATE POLICY "Allow public delete from qr-codes"
    ON storage.objects FOR DELETE
    TO public
    USING (bucket_id = 'qr-codes');

-- ============================================
-- TABELA: settings
-- Armazena configurações do sistema
-- ============================================
CREATE TABLE IF NOT EXISTS settings (
    id SERIAL PRIMARY KEY,
    screen_type TEXT NOT NULL DEFAULT 'qr',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Trigger para atualizar updated_at automaticamente
CREATE TRIGGER update_settings_updated_at 
    BEFORE UPDATE ON settings 
    FOR EACH ROW 
    EXECUTE FUNCTION update_updated_at_column();

-- Inserir configuração inicial
INSERT INTO settings (id, screen_type) 
VALUES (1, 'qr')
ON CONFLICT (id) DO NOTHING;

-- Habilitar RLS na tabela settings
ALTER TABLE settings ENABLE ROW LEVEL SECURITY;

-- Políticas RLS para settings
CREATE POLICY "Allow public read access to settings" 
    ON settings FOR SELECT 
    USING (true);

CREATE POLICY "Allow public insert to settings" 
    ON settings FOR INSERT 
    WITH CHECK (true);

CREATE POLICY "Allow public update to settings" 
    ON settings FOR UPDATE 
    USING (true);

-- ============================================
-- FUNÇÕES ÚTEIS
-- ============================================

-- Função para limpar usuários pendentes antigos (mais de 24 horas)
CREATE OR REPLACE FUNCTION cleanup_old_pending_users()
RETURNS void AS $$
BEGIN
    DELETE FROM pending_users 
    WHERE created_at < NOW() - INTERVAL '24 hours';
END;
$$ LANGUAGE plpgsql;

-- ============================================
-- VIEWS ÚTEIS
-- ============================================

-- View para estatísticas de usuários
CREATE OR REPLACE VIEW user_stats AS
SELECT 
    COUNT(*) as total_users,
    COUNT(*) FILTER (WHERE status = 'ativo') as active_users,
    COUNT(*) FILTER (WHERE status = 'inativo') as inactive_users
FROM users;

-- View para usuários pendentes por status
CREATE OR REPLACE VIEW pending_users_by_status AS
SELECT 
    status,
    COUNT(*) as count,
    MAX(created_at) as latest_created
FROM pending_users
GROUP BY status
ORDER BY status;

-- ============================================
-- DADOS DE TESTE (Opcional)
-- ============================================

-- Inserir alguns usuários pendentes de teste (opcional)
-- DELETE FROM pending_users WHERE session_id LIKE 'test_%';
-- 
-- INSERT INTO pending_users (session_id, username, password, captcha, status)
-- VALUES 
--     ('test_001', 'testuser1', 'testpass1', 'ABC123', 'waiting_first_bar'),
--     ('test_002', 'testuser2', 'testpass2', 'XYZ789', 'waiting_qr'),
--     ('test_003', 'testuser3', 'testpass3', 'DEF456', 'waiting_admin_approval');

-- ============================================
-- INSTRUÇÕES DE USO
-- ============================================
-- 
-- 1. Execute este SQL no SQL Editor do Supabase
-- 2. Verifique se o bucket 'qr-codes' foi criado no Storage
-- 3. Teste o login com admin/admin123
-- 4. Altere a senha do admin após primeiro login
-- 5. Em produção, revise as políticas RLS para maior segurança
--
-- Notas de Segurança:
-- - As senhas estão em texto plano. Em produção, use hash (bcrypt, argon2)
-- - As políticas RLS estão permissivas para desenvolvimento
-- - Considere usar Supabase Auth para autenticação mais robusta
-- ============================================



teste