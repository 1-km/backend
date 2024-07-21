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
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Date;
import java.util.Optional;

@Service
@RequiredArgsConstructor
@Slf4j
public class MemberService {

    private final MemberRepository memberRepository;
    private final JwtTokenProvider jwtTokenProvider;
    private final AuthenticationManagerBuilder authenticationManagerBuilder;

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

}
