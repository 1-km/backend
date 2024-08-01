package military._km.controller;

import jakarta.mail.MessagingException;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import military._km.domain.EmailRequest;
import military._km.domain.EmailResponse;
import military._km.service.MailSendService;
import military._km.service.MailVerifyService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.security.NoSuchAlgorithmException;

@RestController
@RequiredArgsConstructor
@RequestMapping("/email")
public class MailController {

    private final MailSendService sendService;
    private final MailVerifyService verifyService;

    @PostMapping("/send")
    public ResponseEntity<EmailResponse> send(@Valid @RequestBody EmailRequest request) throws MessagingException, NoSuchAlgorithmException {
        EmailResponse emailResponse = sendService.sendForCertification(request.getEmail());
        return new ResponseEntity<>(new EmailResponse(emailResponse.getEmail(), emailResponse.getCertificationNumber()),HttpStatus.OK);
    }

    @GetMapping("/verify")
    public ResponseEntity<HttpStatus> verify(@RequestParam(name = "email") String email, @RequestParam(name = "certificationNumber") String certificationNumber) {
        verifyService.verifyEmail(email, certificationNumber);
        return new ResponseEntity<>(HttpStatus.OK);
    }
}
