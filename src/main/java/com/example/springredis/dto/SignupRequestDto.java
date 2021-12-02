package com.example.springredis.dto;

import lombok.AllArgsConstructor;
import lombok.Data;

@AllArgsConstructor
@Data
public class SignupRequestDto {

    private String username;
    private String password;
    private boolean admin;
}
