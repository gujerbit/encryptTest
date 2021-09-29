package com.gujerbit.encrypt.controller;

import java.io.File;
import java.io.FileOutputStream;
import java.nio.file.Files;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.EncodedKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;
import javax.servlet.http.HttpServletRequest;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import com.gujerbit.encrypt.util.Converter;

@CrossOrigin("*")
@Controller
public class RSAController {
	
	@Autowired
	private Converter converter;

	@GetMapping("/encrypt/RSA")
	public @ResponseBody String encryptRSA(HttpServletRequest req) {
		try {
			PublicKey publicKey = getPublicKey(); //public key 갖고옴
			String value = req.getParameter("param"); //사용자가 입력한 데이터 갖고옴
			Cipher cipher = Cipher.getInstance("RSA"); //RSA로 암호화
			cipher.init(Cipher.ENCRYPT_MODE, publicKey); //암호화 모드로 초기설정
			byte[] encrypt = cipher.doFinal(value.getBytes()); //암호화
			
			return converter.byteToHex(encrypt); //16진수로 변환
		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}
	}
	
	@GetMapping("decrypt/RSA")
	public @ResponseBody String decryptRSA(HttpServletRequest req) {
		try {
			PrivateKey privateKey = getPrivateKey(); //private key 갖고옴
			String value = req.getParameter("param");
			Cipher cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.DECRYPT_MODE, privateKey); //복호화 모드로 초기설정
			byte[] decrypt = cipher.doFinal(converter.hexToByte(value)); //복호화
			
			return new String(decrypt);
		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}
	}
	
	private KeyPair createKeyPair() {
		try {
			KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
			generator.initialize(2048); //2048bit
			KeyPair pair = generator.generateKeyPair();
			FileOutputStream fos1 = new FileOutputStream("src/key/public.key"); //해당 경로에 저장
			fos1.write(pair.getPublic().getEncoded()); //getEncoded 하면 byte로 저장됨
			FileOutputStream fos2 = new FileOutputStream("src/key/private.key");
			fos2.write(pair.getPrivate().getEncoded());
			fos1.close();
			fos2.close();
			
			return pair;
		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}
	}
	
	private boolean existKeyFile() { //파일이 있다면 true 없다면 false
		File file = new File("src/key/public.key");
		
		return file.exists();
	}
	
	private PublicKey getPublicKey() {
		PublicKey publicKey = null;
		
		if(!existKeyFile()) { //파일이 없다면
			KeyPair pair = createKeyPair(); //키 페어 새로 만듬
			publicKey = pair.getPublic(); //공용키 갖고오기
		} else { //파일이 있다면
			try {
				File publicKeyFile = new File("src/key/public.key"); //해당 경로로 파일 설정
				byte[] publicKeyBytes = Files.readAllBytes(publicKeyFile.toPath()); //추상 경로로 갖고온걸 byte로 읽음
				
				KeyFactory factory = KeyFactory.getInstance("RSA"); //keyfactory로 객체 생성
				EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes); //X.509로 변환 -> 공개 키 기반
				publicKey = factory.generatePublic(publicKeySpec); //키 받아오기
			} catch (Exception e) {
				e.printStackTrace();
			}
		}
		
		return publicKey;
	}
	
	private PrivateKey getPrivateKey() {
		PrivateKey privateKey = null;
		
		if(!existKeyFile()) {
			KeyPair pair = createKeyPair();
			privateKey = pair.getPrivate();
		} else {
			try {
				File privateKeyFile = new File("src/key/private.key");
				byte[] privateKeyBytes = Files.readAllBytes(privateKeyFile.toPath());
				
				KeyFactory factory = KeyFactory.getInstance("RSA");
				PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes); //private key는 애로 해야함
				privateKey = factory.generatePrivate(privateKeySpec);
			} catch (Exception e) {
				e.printStackTrace();
			}
		}
		
		return privateKey;
	}
	
}
