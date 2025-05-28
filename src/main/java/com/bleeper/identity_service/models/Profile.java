package com.bleeper.identity_service.models;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@AllArgsConstructor
public class Profile {

    private String username;
    private String imageUrl;

    private String following;
    private String followers;
    private String likes;

    private String bio;
}
