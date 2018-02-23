package onejune.oauth.authserver.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;

@Configuration
@EnableAuthorizationServer
public class AuthServerConfiguration extends AuthorizationServerConfigurerAdapter {

    @Override
    public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
        security.tokenKeyAccess("hasRole('ROLE_TRUSTED')").checkTokenAccess("isAuthenticated()");
    }

    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
        clients.inMemory()
                .withClient("trusted-app")
                    .secret("trusted")
                    .authorizedGrantTypes("authorization_code", "implicit", "password", "client_credentials", "refresh_token")
                    .authorities("ROLE_TRUSTED", "ROLE_CLIENT")
                    .autoApprove(true)
                    .accessTokenValiditySeconds(30000)
                    .scopes("read", "write")
                    .redirectUris("http://localhost:8088/redirect")
                .and()
                .withClient("public-1st-party-app")
                    .secret("public")
                    .authorizedGrantTypes("authorization_code", "implicit", "refresh_token")
                    .authorities("ROLE_CLIENT")
                    .autoApprove(true)
                    .accessTokenValiditySeconds(30000)
                    .scopes("read", "write")
                    .redirectUris("http://localhost:8088/redirect")
                .and()
                .withClient("public-3st-party-app")
                    .secret("public")
                    .authorizedGrantTypes("authorization_code", "implicit", "refresh_token")
                    .authorities("ROLE_CLIENT")
                    .autoApprove(false)
                    .accessTokenValiditySeconds(1800)
                    .scopes("read")
                    .redirectUris("http://localhost:8088/redirect");
    }

    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
        super.configure(endpoints);
    }
}
