-- Script d'initialisation des données de test
-- Ce script ne sera exécuté que si les tables sont vides

-- Insertion des rôles (si ils n'existent pas déjà)
INSERT INTO role (nom, description) 
SELECT 'ROLE_ADMIN', 'Administrateur système'
WHERE NOT EXISTS (SELECT 1 FROM role WHERE nom = 'ROLE_ADMIN');

INSERT INTO role (nom, description) 
SELECT 'ROLE_VALIDATEUR', 'Validateur de contenu'
WHERE NOT EXISTS (SELECT 1 FROM role WHERE nom = 'ROLE_VALIDATEUR');

INSERT INTO role (nom, description) 
SELECT 'ROLE_CONTRIBUTEUR', 'Contributeur de contenu'
WHERE NOT EXISTS (SELECT 1 FROM role WHERE nom = 'ROLE_CONTRIBUTEUR');

-- Insertion des utilisateurs de test (si ils n'existent pas déjà)
INSERT INTO utilisateur (nom, prenom, email, mot_de_passe, statut, derniere_connexion, date_creation)
SELECT 'Hit', 'Admin', 'admin@adcsa.cm', 
       '$2b$12$vZ6aKMYzvoIhFLXdCP592emQI.NT8qf.p.iSvMr/BoNDjjaF1j6Xy',
       'ACTIF', NOW(), NOW()
WHERE NOT EXISTS (SELECT 1 FROM utilisateur WHERE email = 'admin@adcsa.cm');

INSERT INTO utilisateur (nom, prenom, email, mot_de_passe, statut, derniere_connexion, date_creation)
SELECT 'Paul', 'Valideur', 'valideur@adcsa.cm', 
       '$2b$12$ajPAYLnxcTRrrHBV45jDNurbzAHBTLV/6as2Ns4YIpTmdEBu0AruK',
       'ACTIF', NOW(), NOW()
WHERE NOT EXISTS (SELECT 1 FROM utilisateur WHERE email = 'valideur@adcsa.cm');

INSERT INTO utilisateur (nom, prenom, email, mot_de_passe, statut, derniere_connexion, date_creation)
SELECT 'Belinga', 'Contributeur', 'contrib@adcsa.cm', 
       '$2b$12$Mh6Zfh6Lo0Wty6ng.iyuLOaRsa9btcQ/lYxRbVjv1kns05AR1RV/W',
       'ACTIF', NOW(), NOW()
WHERE NOT EXISTS (SELECT 1 FROM utilisateur WHERE email = 'contrib@adcsa.cm');

INSERT INTO utilisateur (nom, prenom, email, mot_de_passe, statut, derniere_connexion, date_creation)
SELECT 'Mahop', 'Bloqué', 'bloque@adcsa.cm', 
       '$2b$12$ZAsOs5Xc/zkY8EgQtGmioOLMeHRu10mD82WtKvnfaTw1bhTo5M6Im',
       'BLOQUE', NOW(), NOW()
WHERE NOT EXISTS (SELECT 1 FROM utilisateur WHERE email = 'bloque@adcsa.cm');

-- Affectation des rôles aux utilisateurs
INSERT INTO utilisateur_role (utilisateur_id, role_id)
SELECT u.id, r.id 
FROM utilisateur u, role r 
WHERE u.email = 'admin@adcsa.cm' AND r.nom = 'ROLE_ADMIN'
AND NOT EXISTS (
    SELECT 1 FROM utilisateur_role ur 
    WHERE ur.utilisateur_id = u.id AND ur.role_id = r.id
);

INSERT INTO utilisateur_role (utilisateur_id, role_id)
SELECT u.id, r.id 
FROM utilisateur u, role r 
WHERE u.email = 'valideur@adcsa.cm' AND r.nom = 'ROLE_VALIDATEUR'
AND NOT EXISTS (
    SELECT 1 FROM utilisateur_role ur 
    WHERE ur.utilisateur_id = u.id AND ur.role_id = r.id
);

INSERT INTO utilisateur_role (utilisateur_id, role_id)
SELECT u.id, r.id 
FROM utilisateur u, role r 
WHERE u.email = 'contrib@adcsa.cm' AND r.nom = 'ROLE_CONTRIBUTEUR'
AND NOT EXISTS (
    SELECT 1 FROM utilisateur_role ur 
    WHERE ur.utilisateur_id = u.id AND ur.role_id = r.id
);

INSERT INTO utilisateur_role (utilisateur_id, role_id)
SELECT u.id, r.id 
FROM utilisateur u, role r 
WHERE u.email = 'bloque@adcsa.cm' AND r.nom = 'ROLE_CONTRIBUTEUR'
AND NOT EXISTS (
    SELECT 1 FROM utilisateur_role ur 
    WHERE ur.utilisateur_id = u.id AND ur.role_id = r.id
);