package cm.adcsa.auth.controller;

import cm.adcsa.auth.dto.request.ChangePasswordRequest;
import cm.adcsa.auth.dto.request.LoginRequest;
import cm.adcsa.auth.dto.request.NewPasswordRequest;
import cm.adcsa.auth.dto.request.ResetPasswordRequest;
import cm.adcsa.auth.dto.response.ApiResponse;
import cm.adcsa.auth.dto.response.LoginResponse;
import cm.adcsa.auth.dto.response.UserInfo;
import cm.adcsa.auth.security.UserPrincipal;
import cm.adcsa.auth.service.AuthService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/auth")
@CrossOrigin(origins = "http://localhost:4200", maxAge = 3600)
public class AuthController {

    private static final Logger logger = LoggerFactory.getLogger(AuthController.class);

    @Autowired
    private AuthService authService;

    @PostMapping("/login")
    public ResponseEntity<ApiResponse<LoginResponse>> login(@Valid @RequestBody LoginRequest loginRequest) {
        logger.info("Tentative de connexion pour l'utilisateur : {}", loginRequest.getEmail());
        
        LoginResponse loginResponse = authService.login(loginRequest);
        
        return ResponseEntity.ok(ApiResponse.success("Connexion réussie", loginResponse));
    }

    @PostMapping("/logout")
    @PreAuthorize("hasRole('USER')")
    public ResponseEntity<ApiResponse<Object>> logout(HttpServletRequest request) {
        String token = getTokenFromRequest(request);
        if (token != null) {
            authService.logout(token);
        }
        
        return ResponseEntity.ok(ApiResponse.success("Déconnexion réussie"));
    }

    @PostMapping("/refresh-token")
    public ResponseEntity<ApiResponse<LoginResponse>> refreshToken(@RequestBody Map<String, String> request) {
        String refreshToken = request.get("refreshToken");
        
        LoginResponse loginResponse = authService.refreshToken(refreshToken);
        
        return ResponseEntity.ok(ApiResponse.success("Token rafraîchi avec succès", loginResponse));
    }

    @PostMapping("/change-password")
    @PreAuthorize("hasRole('USER')")
    public ResponseEntity<ApiResponse<Object>> changePassword(
            @AuthenticationPrincipal UserPrincipal userPrincipal,
            @Valid @RequestBody ChangePasswordRequest request) {
        
        authService.changePassword(userPrincipal.getEmail(), request);
        
        return ResponseEntity.ok(ApiResponse.success("Mot de passe modifié avec succès"));
    }

    @PostMapping("/forgot-password")
    public ResponseEntity<ApiResponse<Object>> forgotPassword(@Valid @RequestBody ResetPasswordRequest request) {
        authService.requestPasswordReset(request);
        
        return ResponseEntity.ok(ApiResponse.success(
                "Si cet email existe dans notre système, vous recevrez un lien de réinitialisation"));
    }

    @PostMapping("/reset-password")
    public ResponseEntity<ApiResponse<Object>> resetPassword(@Valid @RequestBody NewPasswordRequest request) {
        authService.resetPassword(request);
        
        return ResponseEntity.ok(ApiResponse.success("Mot de passe réinitialisé avec succès"));
    }

    @GetMapping("/me")
    @PreAuthorize("hasRole('USER')")
    public ResponseEntity<ApiResponse<UserInfo>> getCurrentUser(@AuthenticationPrincipal UserPrincipal userPrincipal) {
        UserInfo userInfo = new UserInfo(
                userPrincipal.getId(),
                userPrincipal.getNom(),
                userPrincipal.getPrenom(),
                userPrincipal.getEmail(),
                userPrincipal.getAuthorities().stream()
                        .map(authority -> authority.getAuthority())
                        .toList()
        );
        
        return ResponseEntity.ok(ApiResponse.success("Informations utilisateur récupérées", userInfo));
    }

    @GetMapping("/check-auth")
    @PreAuthorize("hasRole('USER')")
    public ResponseEntity<ApiResponse<Object>> checkAuth() {
        return ResponseEntity.ok(ApiResponse.success("Utilisateur authentifié"));
    }

    private String getTokenFromRequest(HttpServletRequest request) {
        String bearerToken = request.getHeader("Authorization");
        if (bearerToken != null && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);
        }
        return null;
    }
}