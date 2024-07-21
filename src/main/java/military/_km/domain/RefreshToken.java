package military._km.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.Data;
import lombok.Getter;
import lombok.Setter;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.redis.core.index.Indexed;

import java.time.LocalDateTime;

@Entity
@Getter @Setter
@Table(name="refresh_token")
public class RefreshToken {

    @Id
    @Column(name = "email")
    private String email;

    @Indexed
    @Column(name = "token")
    private String token;

    @CreatedDate
    private LocalDateTime time;
}
