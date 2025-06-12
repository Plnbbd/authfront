package cm.adcsa.auth.service;

import cm.adcsa.auth.dto.request.ChangePasswordRequest;
import cm.adcsa.auth.dto.request.LoginRequest;
import cm.adcsa.auth.dto.request.NewPasswordRequest;
import cm.adcsa.auth.dto.request.ResetPasswordRequest;
import cm.adcsa.auth.dto.response.LoginResponse;
import cm.adcsa.auth.entity.StatutUtilisateur;
import cm.adcsa.auth.entity.Utilisateur;
import cm.adcsa.auth.exception.AuthenticationException;
import cm.adcsa.auth.exception.BusinessException;
import cm.adcsa.auth.repository.UtilisateurRepository;
import cm.adcsa.auth.security.JwtTokenProvider;
import cm.adcsa.auth.security.UserPrincipal;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

@Service
@Transactional
public class AuthService {

    private static final Logger logger = LoggerFactory.getLogger(AuthService.class);

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private UtilisateurRepository utilisateurRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private JwtTokenProvider tokenProvider;

    @Value("${app.security.max-login-attempts}")
    private int maxLoginAttempts;

    @Value("${app.security.account-lock-duration}")
    private long accountLockDuration;

    public LoginResponse login(LoginRequest loginRequest) {
        try {
            // Vérifier si l'utilisateur existe
            Utilisateur utilisateur = utilisateurRepository.findByEmail(loginRequest.getEmail())
                    .orElseThrow(() -> new AuthenticationException("Email ou mot de passe incorrect"));

            // Vérifier le statut du compte
            if (utilisateur.getStatut() == StatutUtilisateur.BLOQUE) {
                throw new AuthenticationException("Compte bloqué. Contactez l'administrateur.");
            }

            if (utilisateur.getStatut() == StatutUtilisateur.INACTIF) {
                throw new AuthenticationException("Compte inactif. Contactez l'administrateur.");
            }

            // Vérifier si le compte est temporairement verrouillé
            if (isAccountTemporarilyLocked(utilisateur)) {
                throw new AuthenticationException("Compte temporairement verrouillé. Réessayez plus tard.");
            }

            // Authentification
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            loginRequest.getEmail(),
                            loginRequest.getMotDePasse()
                    )
            );

            // Réinitialiser les tentatives de connexion en cas de succès
            resetLoginAttempts(utilisateur);

            // Mettre à jour la dernière connexion
            updateLastLogin(utilisateur);

            // Générer les tokens
            String accessToken = tokenProvider.generateAccessToken(authentication);
            String refreshToken = tokenProvider.generateRefreshToken(authentication);

            // Créer la réponse
            UserPrincipal userPrincipal = (UserPrincipal) authentication.getPrincipal();
            LoginResponse.UtilisateurDto utilisateurDto = new LoginResponse.UtilisateurDto(
                    userPrincipal.getId(),
                    userPrincipal.getNom(),
                    userPrincipal.getPrenom(),
                    userPrincipal.getEmail(),
                    utilisateur.getStatut().name(),
                    utilisateur.getDerniereConnexion(),
                    userPrincipal.getAuthorities().stream()
                            .map(authority -> authority.getAuthority())
                            .collect(Collectors.toList())
            );

            logger.info("Connexion réussie pour l'utilisateur : {}", loginRequest.getEmail());

            return new LoginResponse(accessToken, refreshToken, tokenProvider.getJwtExpiration(), utilisateurDto);

        } catch (BadCredentialsException e) {
            // Gérer les tentatives de connexion échouées
            handleFailedLoginAttempt(loginRequest.getEmail());
            throw new AuthenticationException("Email ou mot de passe incorrect");
        } catch (Exception e) {
            logger.error("Erreur lors de la connexion pour l'utilisateur : {}", loginRequest.getEmail(), e);
            throw new AuthenticationException("Erreur lors de la connexion");
        }
    }

    public void logout(String token) {
        // Ici, vous pouvez ajouter la logique pour blacklister le token
        // ou le stocker dans une cache/base de données des tokens révoqués
        logger.info("Déconnexion effectuée");
    }

    public void changePassword(String email, ChangePasswordRequest request) {
        if (!request.getNouveauMotDePasse().equals(request.getConfirmationMotDePasse())) {
            throw new BusinessException("Les mots de passe ne correspondent pas");
        }

        Utilisateur utilisateur = utilisateurRepository.findByEmail(email)
                .orElseThrow(() -> new BusinessException("Utilisateur non trouvé"));

        if (!passwordEncoder.matches(request.getAncienMotDePasse(), utilisateur.getMotDePasse())) {
            throw new BusinessException("Ancien mot de passe incorrect");
        }

        String nouveauMotDePasseHash = passwordEncoder.encode(request.getNouveauMotDePasse());
        utilisateurRepository.updateMotDePasse(utilisateur.getId(), nouveauMotDePasseHash);

        logger.info("Mot de passe changé pour l'utilisateur : {}", email);
    }

    public void requestPasswordReset(ResetPasswordRequest request) {
        Utilisateur utilisateur = utilisateurRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> new BusinessException("Utilisateur non trouvé avec cet email"));

        String token = UUID.randomUUID().toString();
        LocalDateTime expirationDate = LocalDateTime.now().plusHours(1); // Token valide 1 heure

        utilisateurRepository.updateTokenResetPassword(utilisateur.getId(), token, expirationDate);

        // Ici, vous devriez envoyer un email avec le token
        // emailService.sendPasswordResetEmail(utilisateur.getEmail(), token);

        logger.info("Demande de réinitialisation de mot de passe pour : {}", request.getEmail());
    }

    public void resetPassword(NewPasswordRequest request) {
        if (!request.getNouveauMotDePasse().equals(request.getConfirmationMotDePasse())) {
            throw new BusinessException("Les mots de passe ne correspondent pas");
        }

        Utilisateur utilisateur = utilisateurRepository.findByTokenResetPassword(request.getToken())
                .orElseThrow(() -> new BusinessException("Token invalide"));

        if (utilisateur.getDateExpirationToken() == null ||
            LocalDateTime.now().isAfter(utilisateur.getDateExpirationToken())) {
            throw new BusinessException("Token expiré");
        }

        String nouveauMotDePasseHash = passwordEncoder.encode(request.getNouveauMotDePasse());
        utilisateurRepository.updateMotDePasse(utilisateur.getId(), nouveauMotDePasseHash);
        utilisateurRepository.clearTokenResetPassword(utilisateur.getId());

        logger.info("Mot de passe réinitialisé pour l'utilisateur : {}", utilisateur.getEmail());
    }

    public LoginResponse refreshToken(String refreshToken) {
        if (!tokenProvider.validateToken(refreshToken)) {
            throw new AuthenticationException("Token de rafraîchissement invalide");
        }

        String email = tokenProvider.getEmailFromToken(refreshToken);
        Utilisateur utilisateur = utilisateurRepository.findByEmail(email)
                .orElseThrow(() -> new AuthenticationException("Utilisateur non trouvé"));

        UserPrincipal userPrincipal = UserPrincipal.create(utilisateur);
        Authentication authentication = new UsernamePasswordAuthenticationToken(
                userPrincipal, null, userPrincipal.getAuthorities());

        String newAccessToken = tokenProvider.generateAccessToken(authentication);
        String newRefreshToken = tokenProvider.generateRefreshToken(authentication);

        LoginResponse.UtilisateurDto utilisateurDto = new LoginResponse.UtilisateurDto(
                utilisateur.getId(),
                utilisateur.getNom(),
                utilisateur.getPrenom(),
                utilisateur.getEmail(),
                utilisateur.getStatut().name(),
                utilisateur.getDerniereConnexion(),
                userPrincipal.getAuthorities().stream()
                        .map(authority -> authority.getAuthority())
                        .collect(Collectors.toList())
        );

        return new LoginResponse(newAccessToken, newRefreshToken, tokenProvider.getJwtExpiration(), utilisateurDto);
    }

    private boolean isAccountTemporarilyLocked(Utilisateur utilisateur) {
        if (utilisateur.getDateVerrouillage() == null) {
            return false;
        }
        return LocalDateTime.now().isBefore(utilisateur.getDateVerrouillage().plusNanos(accountLockDuration * 1_000_000));
    }

    private void handleFailedLoginAttempt(String email) {
        utilisateurRepository.findByEmail(email).ifPresent(utilisateur -> {
            int newAttempts = utilisateur.getTentativesConnexion() + 1;
            utilisateurRepository.updateTentativesConnexion(utilisateur.getId(), newAttempts);

            if (newAttempts >= maxLoginAttempts) {
                utilisateurRepository.updateDateVerrouillage(utilisateur.getId(), LocalDateTime.now());
                logger.warn("Compte temporairement verrouillé pour : {}", email);
            }
        });
    }

    private void resetLoginAttempts(Utilisateur utilisateur) {
        Integer tentatives = utilisateur.getTentativesConnexion();
        if (tentatives != null && tentatives > 0) {
            utilisateurRepository.updateTentativesConnexion(utilisateur.getId(), 0);
        }
        if (utilisateur.getDateVerrouillage() != null) {
            utilisateurRepository.updateDateVerrouillage(utilisateur.getId(), null);
        }
    }

    private void updateLastLogin(Utilisateur utilisateur) {
        utilisateurRepository.updateDerniereConnexion(utilisateur.getId(), LocalDateTime.now());
    }
}