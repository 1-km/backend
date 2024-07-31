package military._km.domain;

import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.persistence.*;
import lombok.*;
import military._km.converter.MilitaryConverter;

import java.util.Date;

@Entity
@Builder
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@Getter
@AllArgsConstructor
public class Member extends BaseTimeEntity{

    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "member_id")
    private Long id;
    @Column(nullable = false,name = "member_email")
    private String email;
    @JsonIgnore
    @Column(nullable = false, name = "member_password")
    private String password;
    @Column(nullable = false, name = "member_nickname")
    private String nickname;

    @Convert(converter = MilitaryConverter.class)
    @Column(name="member_military")
    private Military military;

    @Enumerated(EnumType.STRING)
    @Column(name = "member_role")
    private Role role;

    @Column(name = "member_base")
    private String base;

    @Column(name = "member_startdate")
    private String startdate;

    @Column(name = "member_finishdate")
    private String finishdate;

}
