package org.saeta.serviciovalidadorfirma.controller;

import org.saeta.serviciovalidadorfirma.service.SignatureService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import java.util.Map;

@RestController
@RequestMapping("/api/signature")
public class SignatureController {

    @Autowired
    private SignatureService signatureService;

    @PostMapping("/validate")
    public ResponseEntity<Map<String, Object>> validateSignature(@RequestParam("file") MultipartFile file) {
        return signatureService.validateSignature(file);
    }
}