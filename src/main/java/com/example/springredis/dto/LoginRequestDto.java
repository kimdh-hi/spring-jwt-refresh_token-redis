package com.example.springredis.dto;

import lombok.AllArgsConstructor;
import lombok.Data;

@AllArgsConstructor
@Data
public class LoginRequestDto {
    private String username;
    private String password;
}
