INSERT INTO identity_credential_types (id, name) SELECT 'a65f7aa3-5294-48d9-a1f8-e177ecd21740', 'saml' WHERE NOT EXISTS ( SELECT * FROM identity_credential_types WHERE name = 'saml');