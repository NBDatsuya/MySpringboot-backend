package tgkt.code.spb.backend.config;

import jakarta.annotation.Resource;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.BeanUtils;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import tgkt.code.spb.backend.entity.RestBean;
import tgkt.code.spb.backend.entity.dto.Account;
import tgkt.code.spb.backend.entity.vo.response.AuthorizeVO;
import tgkt.code.spb.backend.filter.JWTAuthorizer;
import tgkt.code.spb.backend.service.AccountService;
import tgkt.code.spb.backend.util.JWTUtil;

import java.io.IOException;

@Configuration
public class SecurityConfiguration {
    @Resource
    JWTUtil jwtUtil;

    @Resource
    JWTAuthorizer authorizer;


    @Resource
    AccountService service;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        return http
                .authorizeHttpRequests(conf ->
                        conf
                                .requestMatchers("/api/auth/**").permitAll()
                                .anyRequest().authenticated()
                )
                .formLogin(conf -> conf
                        .loginProcessingUrl("/api/auth/login")
                        .successHandler(this::onAuthenticationSuccess)
                        .failureHandler(this::onAuthenticationFailure)
                )
                .logout(conf -> conf.logoutUrl("/api/auth/logout")
                        .logoutSuccessHandler(this::onLogoutSuccess)
                )
                .csrf(AbstractHttpConfigurer::disable)
                .sessionManagement(conf -> conf
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .addFilterBefore(authorizer, UsernamePasswordAuthenticationFilter.class)
                .exceptionHandling(conf -> conf
                        .authenticationEntryPoint(this::onUnauthorized)
                )
                .build();

    }

    public void onUnauthorized(HttpServletRequest req,
                               HttpServletResponse resp,
                               AuthenticationException e)
            throws IOException, ServletException {

        resp.setContentType("application/json;charset=utf-8");
        resp.getWriter().write(
                RestBean.unauthorized("用户未登录").asJsonString()
        );
    }

    public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response,
                                        Authentication authentication)
            throws IOException, ServletException {
        User user = (User) authentication.getPrincipal();

        // Query for 2 times
        Account account = service.findAccountByNameOrEmail(
                user.getUsername());

        String token = jwtUtil.createJWT(user,
                account.getId(), account.getUsername());

        var aVO = new AuthorizeVO();
        BeanUtils.copyProperties(account, aVO);
        aVO.setExpireTime(jwtUtil.expireTime());
        aVO.setToken(token);

        response.setContentType("application/json;charset=utf-8");
        response.getWriter().write(
                RestBean.success(aVO).asJsonString()
        );
    }

    public void onAuthenticationFailure(HttpServletRequest request,
                                        HttpServletResponse response,
                                        AuthenticationException e)
            throws IOException, ServletException {
        response.setContentType("application/json;charset=utf-8");
        response.getWriter().write(
                RestBean.unauthorized(e.getMessage()).asJsonString()
        );
    }

    public void onLogoutSuccess(HttpServletRequest request,
                                HttpServletResponse response,
                                Authentication authentication)
            throws IOException, ServletException {
        response.setContentType("application/json;charset=utf-8");
        var writer = response.getWriter();
        var auth = request.getHeader("Authorization");
        if (jwtUtil.invalidateJWT(auth)) {
            writer.write(RestBean.success().asJsonString());
        } else {
            writer.write(RestBean.failure(400, "退出登录失败").asJsonString());
        }
    }
}
