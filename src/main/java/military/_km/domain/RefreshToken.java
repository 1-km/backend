package military._km.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Table;
import lombok.Getter;
import lombok.Setter;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.Id;
import org.springframework.data.redis.core.RedisHash;
import org.springframework.data.redis.core.index.Indexed;

import java.time.LocalDateTime;

@Getter @Setter
@RedisHash
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
