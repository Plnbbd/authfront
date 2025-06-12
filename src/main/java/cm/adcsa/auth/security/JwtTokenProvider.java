package cm.adcsa.auth.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SecurityException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

@Component
public class JwtTokenProvider {

    private static final Logger logger = LoggerFactory.getLogger(JwtTokenProvider.class);
    private static final int MIN_SECRET_KEY_LENGTH = 256; // 32 bytes minimum for HS256

    private static final String CLAIM_USER_ID = "userId";
    private static final String CLAIM_EMAIL = "email";
    private static final String CLAIM_NOM = "nom";
    private static final String CLAIM_PRENOM = "prenom";
    private static final String CLAIM_ROLES = "roles";

    @Value("${app.jwt.secret}")
    private String jwtSecret;

    @Value("${app.jwt.expiration}")
    private long jwtExpiration;

    @Value("${app.jwt.refresh-expiration}")
    private long jwtRefreshExpiration;

    private SecretKey getSigningKey() {
        if (jwtSecret == null || jwtSecret.length() < MIN_SECRET_KEY_LENGTH) {
            throw new IllegalStateException("La clé secrète JWT doit faire au moins " + MIN_SECRET_KEY_LENGTH + " caractères");
        }
        byte[] keyBytes = jwtSecret.getBytes(StandardCharsets.UTF_8);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    public String generateAccessToken(Authentication authentication) {
        if (authentication == null || authentication.getPrincipal() == null) {
            throw new IllegalArgumentException("L'authentification ne peut pas être nulle");
        }

        UserPrincipal userPrincipal = (UserPrincipal) authentication.getPrincipal();
        Date expiryDate = new Date(System.currentTimeMillis() + jwtExpiration);

        Map<String, Object> claims = new HashMap<>();
        claims.put(CLAIM_USER_ID, userPrincipal.getId());
        claims.put(CLAIM_EMAIL, userPrincipal.getEmail());
        claims.put(CLAIM_NOM, userPrincipal.getNom());
        claims.put(CLAIM_PRENOM, userPrincipal.getPrenom());
        claims.put(CLAIM_ROLES, userPrincipal.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toList()));

        return Jwts.builder()
                .setClaims(claims)
                .setSubject(userPrincipal.getEmail())
                .setIssuedAt(new Date())
                .setExpiration(expiryDate)
                .signWith(getSigningKey())
                .compact();
    }

    public String generateRefreshToken(Authentication authentication) {
        if (authentication == null || authentication.getPrincipal() == null) {
            throw new IllegalArgumentException("L'authentification ne peut pas être nulle");
        }

        UserPrincipal userPrincipal = (UserPrincipal) authentication.getPrincipal();
        Date expiryDate = new Date(System.currentTimeMillis() + jwtRefreshExpiration);

        return Jwts.builder()
                .setSubject(userPrincipal.getEmail())
                .setIssuedAt(new Date())
                .setExpiration(expiryDate)
                .signWith(getSigningKey())
                .compact();
    }

    public String getEmailFromToken(String token) {
        if (token == null || token.trim().isEmpty()) {
            throw new IllegalArgumentException("Le token ne peut pas être nul ou vide");
        }

        Claims claims = Jwts.parser()
                .verifyWith(getSigningKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();

        return claims.getSubject();
    }

    public Claims getClaimsFromToken(String token) {
        if (token == null || token.trim().isEmpty()) {
            throw new IllegalArgumentException("Le token ne peut pas être nul ou vide");
        }

        return Jwts.parser()
                .verifyWith(getSigningKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    public boolean validateToken(String token) {
        if (token == null || token.trim().isEmpty()) {
            logger.error("Token JWT est nul ou vide");
            return false;
        }

        try {
            Jwts.parser()
                .verifyWith(getSigningKey())
                .build()
                .parseSignedClaims(token);
            return true;
        } catch (SecurityException ex) {
            logger.error("Signature JWT invalide: {}", ex.getMessage());
        } catch (MalformedJwtException ex) {
            logger.error("Token JWT malformé: {}", ex.getMessage());
        } catch (ExpiredJwtException ex) {
            logger.error("Token JWT expiré: {}", ex.getMessage());
        } catch (UnsupportedJwtException ex) {
            logger.error("Token JWT non supporté: {}", ex.getMessage());
        } catch (IllegalArgumentException ex) {
            logger.error("JWT claims string est vide: {}", ex.getMessage());
        } catch (Exception ex) {
            logger.error("Erreur inattendue lors de la validation du token: {}", ex.getMessage());
        }
        return false;
    }

    public boolean isTokenExpired(String token) {
        try {
            Claims claims = getClaimsFromToken(token);
            return claims.getExpiration().before(new Date());
        } catch (Exception e) {
            logger.error("Erreur lors de la vérification de l'expiration du token: {}", e.getMessage());
            return true;
        }
    }

    public Date getExpirationDateFromToken(String token) {
        Claims claims = getClaimsFromToken(token);
        return claims.getExpiration();
    }

    public long getJwtExpiration() {
        return jwtExpiration;
    }

    public long getJwtRefreshExpiration() {
        return jwtRefreshExpiration;
    }
}