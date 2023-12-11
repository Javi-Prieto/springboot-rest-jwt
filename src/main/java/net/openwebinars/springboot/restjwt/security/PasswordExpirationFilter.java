package net.openwebinars.springboot.restjwt.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import net.openwebinars.springboot.restjwt.user.model.User;
import net.openwebinars.springboot.restjwt.user.service.CustomUserDetailsService;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import java.io.IOException;
import java.util.Date;
import java.util.logging.Filter;
import java.util.logging.LogRecord;

public class PasswordExpirationFilter implements Filter {

    public void doFilter(ServletRequest request, ServletResponse response,
                         FilterChain chain) throws IOException, ServletException {
        HttpServletRequest httpRequest = (HttpServletRequest) request;

        if (isUrlExcluded(httpRequest)) {
            chain.doFilter(request, response);
            return;
        }

        System.out.println("PasswordExpirationFilter");

        User user = getLoggedInUser();

        if (user != null && user.isPasswordExpired()) {
            showChangePasswordPage(response, httpRequest, user);
        } else {
            chain.doFilter(httpRequest, response);
        }

    }

    private boolean isUrlExcluded(HttpServletRequest httpRequest)
            throws IOException, ServletException {
        String url = httpRequest.getRequestURL().toString();

        if (url.endsWith(".css") || url.endsWith(".png") || url.endsWith(".js")
                || url.endsWith("/change_password")) {
            return true;
        }

        return false;
    }

    private User getLoggedInUser() {
        Authentication authentication
                = SecurityContextHolder.getContext().getAuthentication();
        Object principal = null;

        if (authentication != null) {
            principal = authentication.getPrincipal();
        }

        if (principal != null && principal instanceof CustomUserDetailsService userDetails) {
            return userDetails.getUser();
        }

        return null;
    }

    private void showChangePasswordPage(ServletResponse response,
                                        HttpServletRequest httpRequest, User user) throws IOException {
        System.out.println("User: " + user.getFullName() + " - Password Expired:");
        System.out.println("Last time password changed: " + user.getPasswordChangedTime());
        System.out.println("Current time: " + new Date());

        HttpServletResponse httpResponse = (HttpServletResponse) response;
        String redirectURL = httpRequest.getContextPath() + "/change_password";
        httpResponse.sendRedirect(redirectURL);
    }

    @Override
    public boolean isLoggable(LogRecord record) {
        return false;
    }
}
