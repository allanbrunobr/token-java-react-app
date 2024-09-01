package com.br.multicloudecore.tokenms.controllers;

import com.br.multicloudecore.tokenms.utils.JwtUtil;
import com.google.auth.oauth2.GoogleCredentials;
import com.google.firebase.FirebaseApp;
import com.google.firebase.FirebaseOptions;
import com.google.firebase.auth.FirebaseAuth;
import com.google.firebase.auth.FirebaseAuthException;
import com.google.firebase.auth.FirebaseToken;
import org.springframework.core.io.ClassPathResource;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;
import java.io.InputStream;
import java.util.Map;

@RestController
@CrossOrigin(origins = "http://localhost:4201/login") // Permite requisições de localhost:4200
public class TokenController {

    private final JwtUtil jwtUtil;

    static {
        try {
            ClassPathResource resource = new ClassPathResource("serviceAccountKey.json");
            InputStream serviceAccount = resource.getInputStream();

            FirebaseOptions options = FirebaseOptions.builder()
                    .setCredentials(GoogleCredentials.fromStream(serviceAccount))
                    .build();

            FirebaseApp.initializeApp(options);
        } catch (IOException e) {
            // Lida com a exceção de forma adequada
            e.printStackTrace();
        }
    }

    public TokenController(JwtUtil jwtUtil) {
        this.jwtUtil = jwtUtil;
    }

    @PostMapping("/generateJwt")
    public java.util.Map<String, String> generateJwt(@RequestBody Map<String, String> firebaseTokenMap) throws FirebaseAuthException, IOException {

        if (FirebaseApp.getApps().isEmpty()) {
            ClassPathResource resource = new ClassPathResource("serviceAccountKey.json");
            InputStream serviceAccount = resource.getInputStream();

            FirebaseOptions options = FirebaseOptions.builder()
                    .setCredentials(GoogleCredentials.fromStream(serviceAccount))
                    .build();

            FirebaseApp.initializeApp(options);
        }
        String firebaseToken = firebaseTokenMap.get("firebaseToken");
        FirebaseToken decodedToken = FirebaseAuth.getInstance().verifyIdToken(firebaseToken);

        String username = decodedToken.getName();
        String email = decodedToken.getEmail();
        String jwt = jwtUtil.generateToken(username, email);
        return java.util.Map.of("token", jwt);
    }
}
