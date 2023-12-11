package net.openwebinars.springboot.restjwt.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import net.openwebinars.springboot.restjwt.user.model.User;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import java.io.IOException;
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

        if (customer != null && customer.isPasswordExpired()) {
            showChangePasswordPage(response, httpRequest, customer);
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

        if (principal != null && principal instanceof CustomerUserDetails) {
            CustomerUserDetails userDetails = (CustomerUserDetails) principal;
            return userDetails.getCustomer();
        }

        return null;
    }

    @Override
    public boolean isLoggable(LogRecord record) {
        return false;
    }
}
