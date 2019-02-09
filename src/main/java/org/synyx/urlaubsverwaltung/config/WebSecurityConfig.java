package org.synyx.urlaubsverwaltung.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.synyx.urlaubsverwaltung.security.SimpleAuthenticationProvider;

@Configuration
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    private final SimpleAuthenticationProvider authenticationProvider;

    @Autowired
    public WebSecurityConfig(SimpleAuthenticationProvider simpleAuthenticationProvider) {
        this.authenticationProvider = simpleAuthenticationProvider;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        super.configure(http);

        http.authorizeRequests()
            .mvcMatchers("/**").authenticated()
            .and().formLogin().loginPage("/login").permitAll().defaultSuccessUrl("/web/overview", false).failureForwardUrl("/login?login_error=1")
            .and()
            .logout().logoutUrl("/logout").logoutSuccessUrl("/login")
            .and()
            .csrf().disable()
            .headers().disable();
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) {

        auth.authenticationProvider(authenticationProvider);
    }

}
