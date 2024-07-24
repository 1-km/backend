package military._km.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import military._km.domain.Member;
import military._km.domain.Role;
import military._km.dto.MemberLoginDto;
import military._km.dto.MemberSignupDto;
import military._km.dto.TokenDto;
import military._km.jwt.JwtTokenProvider;
import military._km.repository.MemberRepository;
import military._km.repository.RefreshTokenRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Duration;
import java.util.Date;
import java.util.Optional;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Slf4j
public class MemberService {

    private final MemberRepository memberRepository;
    private final JwtTokenProvider jwtTokenProvider;
    private final AuthenticationManagerBuilder authenticationManagerBuilder;
    private final RedisTemplate<String, String> redisTemplate;
    private final RefreshTokenRepository refreshTokenRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Transactional
    public Member signup(MemberSignupDto memberSignupDto) {
        Member member = Member.builder()
                .email(memberSignupDto.getEmail())
                .password(passwordEncoder.encode(memberSignupDto.getPassword()))
                .role(Role.ROLE_USER)
                .nickname(memberSignupDto.getNickname())
                .createdAt(new Date(System.currentTimeMillis()).toString())
                .build();

        memberRepository.save(member);

        return member;
    }

    @Transactional
    public TokenDto login(MemberLoginDto loginDto) {
        validate(loginDto);
        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(
                loginDto.getEmail(), loginDto.getPassword()
        );

        Authentication authentication = authenticationManagerBuilder.getObject().authenticate(authenticationToken);
        SecurityContextHolder.getContext().setAuthentication(authentication);
        TokenDto tokenDto = jwtTokenProvider.createTokens(authentication);

        redisTemplate.opsForValue().set(
                loginDto.getEmail(),
                tokenDto.getRefreshToken()
        );

        return tokenDto;
    }

    @Transactional
    public ResponseEntity<HttpStatus> logout(String header) {
        String token = header.substring(7);
        Long expiration = jwtTokenProvider.getExpiration(token);
        String email = SecurityContextHolder.getContext().getAuthentication().getName();
        if (redisTemplate.opsForValue().get(email) != null) {
            redisTemplate.delete(email);
        }

        redisTemplate.opsForValue().set(token, "logout", Duration.ofMillis(expiration));
        return new ResponseEntity<>(HttpStatus.OK);
    }

    @Transactional
    public String reissue(String freshToken) {

        if (freshToken == null || !freshToken.startsWith("Bearer ")) {
            log.info("유효하지 않은 토큰입니다.");
        }
        return freshToken.substring(7);
    }

    @Transactional(readOnly = true)
    public Member findMember(String email) {
        return memberRepository.findByEmail(email).orElseThrow(()-> new IllegalArgumentException("사용자가 없습니다."));
    }
    @Transactional(readOnly = true)
    public Optional<Member> getMember(Long id) {
        return memberRepository.findById(id);
    }

    @Transactional(readOnly = true)
    public Optional<Member> getMember(String email) {
        return memberRepository.findByEmail(email);
    }

    public void deleteMember(Long id) {
        memberRepository.deleteById(id);
    }

    private void validate(MemberLoginDto loginDto) {
        memberRepository.findByEmail(loginDto.getEmail())
                .orElseThrow(() -> new UsernameNotFoundException(loginDto.getEmail() + "해당 유저를 찾을 수 없습니다."));

        if(!passwordEncoder.matches(
                loginDto.getPassword(),
                memberRepository.findByEmail(loginDto.getEmail())
                        .orElseThrow(()-> new BadCredentialsException("비밀번호가 맞지 않습니다.")).getPassword())
        ) {
          log.info("로그인 실패.");
        }
    }

    private String getAuthorities(Authentication authentication) {

        return authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(","));
    }

}
