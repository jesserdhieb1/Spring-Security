package com.example.demo.auth;

import org.springframework.stereotype.Component;

import java.util.Optional;

public interface ApplicationUserDao {
     Optional<ApplicationUser> SelectApplicationUserByUserName(String UserName);
}
