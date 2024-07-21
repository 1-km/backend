package military._km.repository;

import military._km.domain.RefreshToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, String> {
    RefreshToken findByEmail(String email);

    @Query(value = "select r.email from RefreshToken r where r.token = :token")
    String findEmailByToken(String token);
}
