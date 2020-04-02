package com.algaworks.algafood.auth.core;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;
import org.springframework.validation.annotation.Validated;

import lombok.Getter;
import lombok.Setter;

@Validated
@Component
@ConfigurationProperties("algafood.jwt.keystore")
@Getter
@Setter
public class JwtKeyStoreProperties {

	private String path;
	
	private String password;
	
	private String keypairAlias;
	
}
