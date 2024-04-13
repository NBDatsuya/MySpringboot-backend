package tgkt.code.spb.backend;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@SpringBootTest
class BackendApplicationTests {

    @Test
    void generateAPassword() {
        String source = "1234";
        var encoder = new BCryptPasswordEncoder();
        System.out.println(
                encoder.encode(source)
        );
    }

}
