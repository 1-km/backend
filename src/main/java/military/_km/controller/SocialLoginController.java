package military._km.controller;

import java.util.Collections;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;

import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdTokenVerifier;
import com.google.api.client.googleapis.javanet.GoogleNetHttpTransport;
import com.google.api.client.json.jackson2.JacksonFactory;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import military._km.dto.IdTokenRequest;
import military._km.dto.TokenDto;
import military._km.service.GoogleOAuthService;

@Controller
@Slf4j
@RequiredArgsConstructor
@RequestMapping("/auth")
public class SocialLoginController {
	@Value("${spring.security.oauth2.client.registration.google.client-id}")
	private String googleClientId;

	private final GoogleOAuthService googleOAuthService;

	@PostMapping("/google")
	public ResponseEntity<?> authenticateGoogleUser(@RequestBody IdTokenRequest request) throws Exception {
		GoogleIdTokenVerifier verifier = new GoogleIdTokenVerifier.Builder(
			GoogleNetHttpTransport.newTrustedTransport(),
			JacksonFactory.getDefaultInstance())
			.setAudience(Collections.singletonList(googleClientId))
			.build();

		GoogleIdToken idToken = verifier.verify(request.getIdToken());
		if(idToken != null){
			try {
				TokenDto tokenDto = googleOAuthService.login(idToken);
				return ResponseEntity.ok(tokenDto);
			} catch (IllegalArgumentException e) {
				return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Not Registered");
			}
		} else {
			// 사용자 인증 실패
			return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid ID token");
		}
	}
}
