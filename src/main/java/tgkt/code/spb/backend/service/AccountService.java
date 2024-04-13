package tgkt.code.spb.backend.service;

import com.baomidou.mybatisplus.extension.service.IService;
import org.springframework.security.core.userdetails.UserDetailsService;
import tgkt.code.spb.backend.entity.dto.Account;

public interface AccountService extends IService<Account> ,
        UserDetailsService {
    Account findAccountByNameOrEmail(String text);
}
