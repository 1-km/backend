package military._km.jwt;

import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import military._km.domain.RefreshToken;
import military._km.domain.Role;
import military._km.dto.TokenDto;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Component;


import javax.crypto.SecretKey;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

@Component
@Slf4j
public class JwtTokenProvider {

    @Autowired
    UserDetailsService userDetailsService;

    private final RedisTemplate<String, String> redisTemplate;

    private static final String AUTHORITIES_KEY = "auth";
    private static final String BEARER_TYPE = "Bearer";
    private final SecretKey key;

    private final static Long ACCESS_TOKEN_EXPIRE_TIME = 30 * 60 * 1000L;
    private final static Long REFRESH_TOKEN_EXPIRE_TIME = 7 * 24 * 60 * 60 * 1000L;

    public JwtTokenProvider(@Value("${jwt.secret}") String secretKey,
                            RedisTemplate<String, String> redisTemplate) {
        byte[] keyBytes = Decoders.BASE64.decode(secretKey);
        this.key = Keys.hmacShaKeyFor(keyBytes);
        this.redisTemplate = redisTemplate;
    }

    /*
       AccessToken 생성
    */
    public String createAccessToken(Authentication authentication) {
        Date now = new Date();
        Date access_expire = new Date(now.getTime() + ACCESS_TOKEN_EXPIRE_TIME);

        String authorities = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(","));

        return Jwts.builder()
                .subject(authentication.getName())
                .claim("email", authentication.getName())
                .claim(AUTHORITIES_KEY,authorities)
                .issuedAt(now)
                .expiration(access_expire)
                .signWith(key)
                .compact();
    }

    /*
       RefreshToken 생성
    */
    public String createRefreshToken(Authentication authentication) {
        Date now = new Date();
        Date refresh_expire = new Date(now.getTime() + REFRESH_TOKEN_EXPIRE_TIME);

        String authorities = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(","));

        String refreshToken = Jwts.builder()
                .subject(authentication.getName())
                .claim("email", authentication.getName())
                .claim(AUTHORITIES_KEY,authorities)
                .issuedAt(now)
                .expiration(refresh_expire)
                .signWith(key)
                .compact();

        redisTemplate.opsForValue().set(
                authentication.getName(),
                refreshToken,
                REFRESH_TOKEN_EXPIRE_TIME,
                TimeUnit.MILLISECONDS
        );

        return refreshToken;
    }

    public TokenDto createTokens(Authentication authentication) {
        String accessToken = createAccessToken(authentication);
        String refreshToken = createRefreshToken(authentication);
        String email = authentication.getName();

        log.info("email = {}", email);
        log.info("accessToken = {}", accessToken);
        log.info("refreshToken = {}", refreshToken);

        return new TokenDto(accessToken, refreshToken);
    }

    public Authentication getAuthentication(String token) {
        Claims claims = Jwts.parser()
                .verifyWith(key)
                .build()
                .parseSignedClaims(token)
                .getPayload();

        Collection<? extends GrantedAuthority> authorities = Arrays.stream(claims.get(AUTHORITIES_KEY).toString().split(","))
                .map(SimpleGrantedAuthority::new)
                .toList();

        User user = new User(claims.getSubject(), "", authorities);

        return new UsernamePasswordAuthenticationToken(user, token, authorities);

    }

    public boolean validateToken(String token) {
        try {
            Jwts.parser().verifyWith(key).build().parseSignedClaims(token);
            return true;
        } catch (ExpiredJwtException e) {
            log.info("토큰이 만료 되었습니다.");
        } catch (JwtException e) {
           log.info("잘못된 토큰입니다.");
        }
        return false;
    }

}
