package military._km.controller;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import military._km.domain.Member;
import military._km.dto.MemberLoginDto;
import military._km.dto.MemberSignupDto;
import military._km.dto.TokenDto;
import military._km.jwt.JwtTokenProvider;
import military._km.service.MemberService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.*;

@RestController
@RequiredArgsConstructor
@Slf4j
public class MemberController {

    private final MemberService memberService;
    private final JwtTokenProvider jwtTokenProvider;

    @PostMapping("/login")
    public ResponseEntity<TokenDto> login(@Valid @RequestBody MemberLoginDto memberLoginDto) {
        try {
            TokenDto tokenDto = memberService.login(memberLoginDto);
            return new ResponseEntity<>(new TokenDto(tokenDto.getGrantType(), tokenDto.getAccessToken(), tokenDto.getRefreshToken()), HttpStatus.OK);
        } catch (AuthenticationException e) {
            return new ResponseEntity<>(HttpStatus.UNAUTHORIZED);
        }
    }

    @PostMapping("/signup")
    public ResponseEntity<HttpStatus> signup(@Valid @RequestBody MemberSignupDto memberSignupDto) {
        Member member = memberService.signup(memberSignupDto);
        if (member.getId() != null) {
            return new ResponseEntity<>(HttpStatus.CREATED);
        } else {
            log.info("회원가입에 실패하였습니다.");
            return new ResponseEntity<>(HttpStatus.BAD_REQUEST);
        }

    }

    @PostMapping("/member/logout")
    public ResponseEntity<HttpStatus> logout(HttpServletRequest request) {
        String header = request.getHeader("Authorization");
        log.info("header={}", header);
        String email = SecurityContextHolder.getContext().getAuthentication().getName();
        log.info("email={}", email);
        return memberService.logout(header);
    }


}
