package military._km.domain;

import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.persistence.*;
import lombok.*;

@Entity
@Builder
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@Getter
@AllArgsConstructor
public class Member {

    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "member_id")
    private Long id;
    @Column(nullable = false)
    private String email;
    @JsonIgnore
    @Column(nullable = false)
    private String password;
    private String nickname;

    @Enumerated(EnumType.STRING)
    private Role role;

    @Column(name = "created")
    private String createdAt;

}
