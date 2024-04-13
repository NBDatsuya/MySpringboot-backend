package tgkt.code.spb.backend.filter;

import com.auth0.jwt.interfaces.DecodedJWT;
import jakarta.annotation.Resource;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import tgkt.code.spb.backend.util.JWTUtil;

import java.io.IOException;

@Component
public class JWTAuthorizer extends OncePerRequestFilter {

    @Resource
    JWTUtil util;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain)
            throws ServletException, IOException {
        String auth = request.getHeader("Authorization");
        DecodedJWT dJWT = util.resolveJWT(auth);
        if (dJWT != null) {
            UserDetails user = util.toUser(dJWT);
            UsernamePasswordAuthenticationToken
                    aToken =
                    new UsernamePasswordAuthenticationToken(
                            user,
                            null,
                            user.getAuthorities()
                    );

            aToken.setDetails(new WebAuthenticationDetailsSource()
                    .buildDetails(request));

            SecurityContextHolder
                    .getContext()
                    .setAuthentication(aToken);

            //request.setAttribute("id", util.toId(dJWT));
        }

        filterChain.doFilter(request, response);
    }
}
