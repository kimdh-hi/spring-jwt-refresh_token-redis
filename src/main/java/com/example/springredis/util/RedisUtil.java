package com.example.springredis.util;

import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ValueOperations;
import org.springframework.stereotype.Component;

import java.time.Duration;

@RequiredArgsConstructor
@Component
public class RedisUtil {

    private final StringRedisTemplate redisTemplate;

    public String getValue(String key) {
        ValueOperations<String, String> ops = redisTemplate.opsForValue();
        return ops.get(key);
    }

    public void setValue(String key, String value, long durationOfSeconds) {
        ValueOperations<String, String> ops = redisTemplate.opsForValue();
        Duration duration = Duration.ofSeconds(durationOfSeconds);
        ops.set(key, value, duration);
    }

    public void deleteValue(String key) {
        redisTemplate.delete(key);
    }
}
