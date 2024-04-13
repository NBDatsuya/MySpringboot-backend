package tgkt.code.spb.backend.entity.dto;

import com.baomidou.mybatisplus.annotation.TableId;
import com.baomidou.mybatisplus.annotation.TableName;
import lombok.AllArgsConstructor;
import lombok.Data;

import java.util.Date;

@Data
@TableName("account")
@AllArgsConstructor
public class Account {
    @TableId
    String id;
    String username;
    String password;
    String email;

    // Simplified
    String role;
    Date regTime;
}
