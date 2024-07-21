package military._km.controller;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import military._km.dto.MemberLoginDto;
import military._km.dto.TokenDto;
import military._km.jwt.JwtTokenProvider;
import military._km.repository.MemberRepository;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.*;

@RestController
@RequiredArgsConstructor
public class LoginController {

    private final AuthenticationManagerBuilder authenticationManagerBuilder;
    private final JwtTokenProvider jwtTokenProvider;

    @PostMapping("/login")
    public ResponseEntity<TokenDto> login(@Valid @RequestBody MemberLoginDto memberLoginDto) {
        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(
                memberLoginDto.getEmail(), memberLoginDto.getPassword()
        );

        try {
            Authentication authentication = authenticationManagerBuilder.getObject().authenticate(authenticationToken);
            SecurityContextHolder.getContext().setAuthentication(authentication);

            TokenDto tokenDto = jwtTokenProvider.createTokens(authentication);

            return new ResponseEntity<>(new TokenDto(tokenDto.getAccessToken(), tokenDto.getRefreshToken()), HttpStatus.OK);
        } catch (AuthenticationException e) {
            return new ResponseEntity<>(HttpStatus.UNAUTHORIZED);
        }
    }

}
