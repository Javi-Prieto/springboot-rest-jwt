package net.openwebinars.springboot.restjwt.security.jwt.refresh;

import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import net.openwebinars.springboot.restjwt.security.errorhandling.RefreshException;
import net.openwebinars.springboot.restjwt.user.model.User;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class RefreshTokenService {

    private final RefreshTokenRepository refreshTokenRepository;

    @Value("${jwt.refresh.duration}")
    private int durationInMinutes;

    public Optional<RefreshToken> findByToken(String token) {
        return refreshTokenRepository.findByToken(token);
    }

    public RefreshToken createRefreshToken(User user) {
        RefreshToken refreshToken = RefreshToken.builder()
                .user(user)
                .token(UUID.randomUUID().toString())
                .expiryDate(Instant.now().plusSeconds(durationInMinutes * 60L))
                .build();
        return refreshTokenRepository.save(refreshToken);
    }
    public RefreshToken verify(RefreshToken refreshToken) {

        if (refreshToken.getExpiryDate().compareTo(Instant.now()) < 0) {
            refreshTokenRepository.delete(refreshToken);
            throw new RefreshException(refreshToken.getToken(), "token de refresco expirado");

        }

        return refreshToken;


    }

    @Transactional
    public void deleteByUser(User user) {
        refreshTokenRepository.deleteByUser(user);
    }
}
