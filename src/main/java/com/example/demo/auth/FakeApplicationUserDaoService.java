package com.example.demo.auth;

import com.google.common.collect.Lists;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Repository;

import static com.example.demo.security.ApplicationUserRole.*;

import java.util.List;
import java.util.Optional;

@Repository("fake")
public class FakeApplicationUserDaoService implements ApplicationUserDao{

    private final PasswordEncoder passwordEncoder;

    @Autowired
    public FakeApplicationUserDaoService(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public Optional<ApplicationUser> SelectApplicationUserByUserName(String UserName) {
        return
                getApplicationUsers()
                        .stream()
                        .filter(applicationUser -> UserName.equals(applicationUser.getUsername()))
                        .findFirst();
    }

    private List<ApplicationUser> getApplicationUsers(){
        List<ApplicationUser> applicationUsers= Lists.newArrayList(
            new ApplicationUser(
                    "jesserdhieb",
                    passwordEncoder.encode("password"),
                    STUDENT.getGrantedAuthorities(),
                    true,
                    true,
                    true,
                    true
            ),
                new ApplicationUser(
                        "amenidhieb",
                        passwordEncoder.encode("password"),
                        ADMIN.getGrantedAuthorities(),
                        true,
                        true,
                        true,
                        true
                ),
                new ApplicationUser(
                        "ghaiethdhieb",
                        passwordEncoder.encode("password"),
                        ADMINTRAINEE.getGrantedAuthorities(),
                        true,
                        true,
                        true,
                        true
                )
        );
        return applicationUsers;
    }
}
