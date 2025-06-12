# Backend d'Authentification ADCSA

Backend Spring Boot pour le système d'authentification ADCSA avec JWT, gestion des rôles et sécurité avancée.

## Fonctionnalités

### Authentification
- Connexion avec email/mot de passe
- Génération de tokens JWT (access + refresh)
- Déconnexion sécurisée
- Gestion des tentatives de connexion
- Verrouillage temporaire des comptes

### Gestion des mots de passe
- Changement de mot de passe
- Réinitialisation par email
- Validation de complexité
- Hashage sécurisé avec BCrypt

### Sécurité
- Protection CORS configurée
- Gestion des rôles (ADMIN, VALIDATEUR, CONTRIBUTEUR)
- Contrôle d'accès basé sur les permissions
- Sessions timeout
- Protection contre les attaques par force brute

## Technologies utilisées

- **Spring Boot 3.2.0**
- **Spring Security 6**
- **JWT (JSON Web Tokens)**
- **PostgreSQL**
- **JPA/Hibernate**
- **Bean Validation**

## Configuration

### Base de données
Configurez votre base de données PostgreSQL dans `application.yml` :

```yaml
spring:
  datasource:
    url: jdbc:postgresql://localhost:5432/adcsa_auth
    username: votre_username
    password: votre_password
```

### Variables d'environnement
- `DB_USERNAME` : Nom d'utilisateur de la base de données
- `DB_PASSWORD` : Mot de passe de la base de données
- `JWT_SECRET` : Clé secrète pour signer les tokens JWT

### Profils
- `dev` : Développement avec logs détaillés
- `prod` : Production avec configuration sécurisée

## Démarrage

1. Cloner le projet
2. Configurer la base de données PostgreSQL
3. Exécuter les scripts de création des tables
4. Démarrer l'application :

```bash
mvn spring-boot:run
```

Ou avec un profil spécifique :

```bash
mvn spring-boot:run -Dspring.profiles.active=dev
```

## API Endpoints

### Authentification
- `POST /api/auth/login` - Connexion
- `POST /api/auth/logout` - Déconnexion
- `POST /api/auth/refresh-token` - Rafraîchissement du token
- `GET /api/auth/me` - Informations utilisateur actuel
- `GET /api/auth/check-auth` - Vérification d'authentification

### Gestion des mots de passe
- `POST /api/auth/change-password` - Changement de mot de passe
- `POST /api/auth/forgot-password` - Demande de réinitialisation
- `POST /api/auth/reset-password` - Réinitialisation avec token

## Données de test

Les utilisateurs suivants sont créés automatiquement :

| Email | Mot de passe | Rôle | Statut |
|-------|-------------|------|--------|
| admin@adcsa.cm | admin123 | ROLE_ADMIN | ACTIF |
| valideur@adcsa.cm | valideur123 | ROLE_VALIDATEUR | ACTIF |
| contrib@adcsa.cm | contrib123 | ROLE_CONTRIBUTEUR | ACTIF |
| bloque@adcsa.cm | bloque123 | ROLE_CONTRIBUTEUR | BLOQUE |

## Sécurité

### JWT
- Tokens d'accès : 24 heures
- Tokens de rafraîchissement : 30 jours
- Signature HMAC avec clé secrète

### Protection des comptes
- 5 tentatives de connexion maximum
- Verrouillage temporaire de 30 minutes
- Gestion des statuts de compte (ACTIF, BLOQUE, INACTIF)

### Validation des mots de passe
- Minimum 8 caractères
- Au moins une minuscule, une majuscule
- Au moins un chiffre et un caractère spécial

## Structure du projet

```
src/main/java/cm/adcsa/auth/
├── config/          # Configuration Spring
├── controller/      # Contrôleurs REST
├── dto/            # Objets de transfert de données
├── entity/         # Entités JPA
├── exception/      # Gestion des exceptions
├── repository/     # Repositories JPA
├── security/       # Configuration sécurité
└── service/        # Services métier
```

## Logs

Les logs sont configurés pour afficher :
- Les tentatives de connexion
- Les erreurs d'authentification
- Les actions de sécurité importantes
- Les requêtes SQL (en mode développement)

## Production

Pour déployer en production :
1. Utiliser le profil `prod`
2. Configurer les variables d'environnement
3. Activer HTTPS
4. Configurer un reverse proxy (nginx/Apache)
5. Monitorer les logs de sécurité"# authfront" 
