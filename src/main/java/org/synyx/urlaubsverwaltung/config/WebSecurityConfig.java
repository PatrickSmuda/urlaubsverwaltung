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
            //.mvcMatchers("/**").authenticated()
            // API
            .mvcMatchers("/api/sicknotes/**").hasAuthority("OFFICE")
            .mvcMatchers("/api/**").hasAuthority("USER")
            // WEB
            .mvcMatchers("/web/overview").hasAuthority("USER")
            .mvcMatchers("/web/application/**").hasAuthority("USER")
            .mvcMatchers("/web/sicknote/**").hasAuthority("USER")
            .mvcMatchers("/web/staff/**").hasAuthority("USER")
            .mvcMatchers("/web/overtime/**").hasAuthority("USER")
            .mvcMatchers("/web/department/**").hasAuthority("USER")
            .mvcMatchers("/web/settings/**").hasAuthority("USER")
            .mvcMatchers("/web/google-api-handshake/**").hasAuthority("USER")
            // sprint boot actuator
            .mvcMatchers("${management.context-path}/health").permitAll()
            .mvcMatchers("${management.context-path}/**").hasAnyAuthority("${management.security.roles}")
            // OPEN
            .and().formLogin().loginPage("/login").permitAll().defaultSuccessUrl("/web/overview", false).failureForwardUrl("/login?login_error=1")
            .and()
            .logout().logoutUrl("/logout").logoutSuccessUrl("/login")
            .and()
            .csrf().disable()
            // TODO: dev-env
            .headers().disable();
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) {

        auth.authenticationProvider(authenticationProvider);
    }

}
