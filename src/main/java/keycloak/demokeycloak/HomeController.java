package keycloak.demokeycloak;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HomeController {

    @GetMapping("/authenticate")
    public String authenticate(Authentication authentication) {
        if (authentication != null && authentication.isAuthenticated()) {
            System.out.println( "Authenticated User: " + authentication.getName() +
                    "\nRole: " + authentication.getAuthorities());
            return "Authenticated User: " + authentication.getName() +
                    "\nRole: " + authentication.getAuthorities() + " " + authentication.getPrincipal().toString();
        } else {
            return "Authentication failed";
        }
    }

    @GetMapping("/")
    public String home() {
        return "Welcome to the home page!";
    }

    @GetMapping("/user/userEndpoint")
    @PreAuthorize("hasRole('USER')")
    public String userEndpoint(@AuthenticationPrincipal OidcUser user) {
        return "Welcome to the user endpoint, " + user.getPreferredUsername() + "!";
    }

    @GetMapping("/admin/adminEndpoint")
    @PreAuthorize("hasRole('ADMIN')")
    public String adminEndpoint(@AuthenticationPrincipal OidcUser user) {
        return "Welcome to the admin endpoint, " + user.getPreferredUsername() + "!";
    }
}
