package tgkt.code.spb.backend.entity.vo.response;

import lombok.Builder;
import lombok.Data;
import lombok.experimental.SuperBuilder;

import java.util.Date;

@Data
public class AuthorizeVO {
    String username;
    String email;
    String role;
    String token;
    Date expireTime;
}
