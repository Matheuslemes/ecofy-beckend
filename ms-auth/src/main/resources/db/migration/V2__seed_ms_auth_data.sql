-- PERMISSIONS & ROLES BÁSICOS

INSERT INTO auth_permissions (name, description, domain)
VALUES
    ('auth:user:read',   'Permite leitura de usuários de autenticação',       'auth'),
    ('auth:user:write',  'Permite criação/alteração de usuários de auth',     'auth'),
    ('auth:user:admin',  'Permite operações administrativas de auth',         'auth'),
    ('auth:client:read', 'Permite leitura de client applications',            'auth'),
    ('auth:client:write','Permite criação/alteração de client applications',  'auth')
ON CONFLICT (name) DO NOTHING;

INSERT INTO auth_roles (name, description)
VALUES
    ('ROLE_ADMIN', 'Administrador da plataforma EcoFy'),
    ('ROLE_USER',  'Usuário padrão da plataforma EcoFy')
ON CONFLICT (name) DO NOTHING;

-- ROLE_ADMIN herda todas as permissões
INSERT INTO auth_roles_permissions (role_name, permission_name)
SELECT 'ROLE_ADMIN', p.name
FROM auth_permissions p
ON CONFLICT (role_name, permission_name) DO NOTHING;

-- ROLE_USER tem apenas leitura básica de si mesmo
INSERT INTO auth_roles_permissions (role_name, permission_name)
VALUES
    ('ROLE_USER', 'auth:user:read')
ON CONFLICT (role_name, permission_name) DO NOTHING;

-- CLIENT APPLICATION PARA ECOFY DASHBOARD (DEV)

INSERT INTO auth_client_applications (
    id,
    client_id,
    client_secret_hash,
    name,
    client_type,
    first_party,
    active,
    created_at,
    updated_at
)
VALUES (
    '00000000-0000-0000-0000-000000000001',
    'eco_dashboard_local',
    '$2a$10$PLACEHOLDERCLIENTSECRETHASHxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx',
    'EcoFy Dashboard (Local Dev)',
    'SPA',
    TRUE,
    TRUE,
    NOW(),
    NOW()
)
ON CONFLICT (id) DO NOTHING;

-- Grants suportados
INSERT INTO auth_client_grants (client_id, grant_type)
VALUES
    ('eco_dashboard_local', 'AUTHORIZATION_CODE'),
    ('eco_dashboard_local', 'REFRESH_TOKEN')
ON CONFLICT (client_id, grant_type) DO NOTHING;

-- Redirect URIs
INSERT INTO auth_client_redirect_uris (client_id, redirect_uri)
VALUES
    ('eco_dashboard_local', 'http://localhost:3000/auth/callback')
ON CONFLICT (client_id, redirect_uri) DO NOTHING;

-- Scopes
INSERT INTO auth_client_scopes (client_id, scope)
VALUES
    ('eco_dashboard_local', 'openid'),
    ('eco_dashboard_local', 'profile'),
    ('eco_dashboard_local', 'email')
ON CONFLICT (client_id, scope) DO NOTHING;

-- JWK "placeholder" (chave pública)
INSERT INTO auth_jwk_keys (key_id, public_key_pem, algorithm, "use", created_at, active)
VALUES (
    'ecofy-auth-key-1',
    '-----BEGIN PUBLIC KEY-----\nREPLACE_ME_WITH_REAL_PEM\n-----END PUBLIC KEY-----',
    'RS256',
    'sig',
    NOW(),
    TRUE
)
ON CONFLICT (key_id) DO NOTHING;
