package com.gujerbit.encrypt.controller;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.Random;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.servlet.http.HttpServletRequest;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@CrossOrigin("*")
@Controller
public class EncryptController {
	
	@GetMapping("/encrypt/SHA-224")
	public @ResponseBody String encryptSHA224(HttpServletRequest req) {
		try {
			String value = req.getParameter("param");
			MessageDigest md = MessageDigest.getInstance("SHA-224");
			byte[] messageDigest = md.digest((value + createSalt()).getBytes()); //salt랑 같이 digest
			//new BigInteger 앞에 숫자 -1,0,1만 됨
			//-1 = 음수, 1 = 양수
			//1을 해주는 이유는 byte를 unsigned 해주기 위해
			//unsigned = 오직 양수만 허용됨
			//암호화할 때는 무조건 unsigned
			//signed는 -128~127 범위
			//unsigned는 0~255 범위
			//헥사코드로 표현해야하기 때문에 16진수인 unsigned
			BigInteger bi = new BigInteger(1, messageDigest);
			String hashText = bi.toString(16); //16진수로 변환하여 헥사코드로 표현
			
			while(hashText.length() < 32) hashText = "0" + hashText;
			
			return hashText;
		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}
	}
	
	@GetMapping("/encrypt/SHA-256")
	public @ResponseBody String encryptSHA256(HttpServletRequest req) {
		try {
			String value = req.getParameter("param");
			MessageDigest md = MessageDigest.getInstance("SHA-256");
			
			return String.format("%064x", new BigInteger(1, md.digest((value + createSalt()).getBytes()))); //총 64자리의 16진수에서 값이 들어가지 못한 자리는 0으로 채움
		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}
	}
	
	@GetMapping("/encrypt/SHA-384")
	public @ResponseBody String encryptSHA384(HttpServletRequest req) {
		try {
			String value = req.getParameter("param");
			MessageDigest md = MessageDigest.getInstance("SHA-384");
			byte[] messageDigest = md.digest((value + createSalt()).getBytes());
			
			return new BigInteger(1, messageDigest).toString(16);
		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}
	}
	
	@GetMapping("/encrypt/SHA-512")
	public @ResponseBody String encryptSHA512(HttpServletRequest req) {
		try {
			String value = req.getParameter("param");
			MessageDigest md = MessageDigest.getInstance("SHA-512");
			
			return String.format("%0128x", new BigInteger(1, md.digest((value + createSalt()).getBytes()))); //128자리의 16진수에서 값이 들어가지 못한 자리는 0으로 채움
		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}
	}
	
	@GetMapping("/encrypt/AES-CBC") //256 = key length -> 32byte, iv는 키 값과 무관하게 16byte
	public @ResponseBody String encryptAESCBC(HttpServletRequest req) {
		try {
			String value = req.getParameter("param");
			String iv = req.getParameter("iv");
			String key = req.getParameter("key");
			Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			SecretKeySpec ss = new SecretKeySpec(key.getBytes(), "AES"); //지정된 알고리즘으로부터 바이트 배열을 넘겨받아 키 구축
			IvParameterSpec ips = new IvParameterSpec(iv.getBytes()); //iv값 생성
			cipher.init(Cipher.ENCRYPT_MODE, ss, ips); //암호화 모드로 초기화
			byte[] encrypt = cipher.doFinal(value.getBytes()); //초기화 모드에 따라서 작업
			
			return new BigInteger(1, encrypt).toString(16); //16진수로 변환
		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}
	}
	
	@GetMapping("/decrypt/AES-CBC")
	public @ResponseBody String decryptAESCBC(HttpServletRequest req) {
		try {
			String value = req.getParameter("param");
			String iv = req.getParameter("iv");
			String key = req.getParameter("key");
			Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			SecretKeySpec ss = new SecretKeySpec(key.getBytes(), "AES");
			IvParameterSpec ips = new IvParameterSpec(iv.getBytes());
			cipher.init(Cipher.DECRYPT_MODE, ss, ips); //복호화 모드로 초기화
			byte[] hexResult = new BigInteger(value, 16).toByteArray(); //16진수를 바이트로 변환
			byte[] decrypt = cipher.doFinal(hexResult);
			
			return new String(decrypt);
		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}
	}
	
	@GetMapping("/encrypt/AES-GCM") //256 = key length -> 32byte, iv는 키 값과 무관하게 16byte
	public @ResponseBody String encryptAESGCM(HttpServletRequest req) {
		try {
			String value = req.getParameter("param");
			String iv = req.getParameter("iv");
			String key = req.getParameter("key");
			Cipher cipher = Cipher.getInstance("AES/GCM/PKCS5Padding");
			SecretKeySpec ss = new SecretKeySpec(key.getBytes(), "AES");
			GCMParameterSpec gps = new GCMParameterSpec(128, iv.getBytes()); //지정된 태그의 길이 및 iv값을 사용
			cipher.init(Cipher.ENCRYPT_MODE, ss, gps);
			byte[] encrypt = cipher.doFinal(value.getBytes());
			
			return new BigInteger(1, encrypt).toString(16);
		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}
	}
	
	@GetMapping("/decrypt/AES-GCM")
	public @ResponseBody String decryptAESGCM(HttpServletRequest req) {
		try {
			String value = req.getParameter("param");
			String iv = req.getParameter("iv");
			String key = req.getParameter("key");
			Cipher cipher = Cipher.getInstance("AES/GCM/PKCS5Padding");
			SecretKeySpec ss = new SecretKeySpec(key.getBytes(), "AES");
			GCMParameterSpec gps = new GCMParameterSpec(128, iv.getBytes());
			cipher.init(Cipher.DECRYPT_MODE, ss, gps);
			byte[] hexResult = new BigInteger(value, 16).toByteArray();
			byte[] decrypt = cipher.doFinal(hexResult);
			
			return new String(decrypt);
		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}
	}
	
	private String createSalt() {
		Random rnd = new Random();
		String result = "";
		
		for(int i = 0; i < 32; i++) {
			int select = rnd.nextInt(3); //0~2
			if(select == 0) result += String.valueOf((char) (rnd.nextInt(26) + 65)); //ASCII 변환 대문자 65~90까지
			else if(select == 1) result += String.valueOf((char) (rnd.nextInt(26) + 97)); //소문자 97부터 122까지
			else result += String.valueOf(rnd.nextInt(10)); //0~9
		}
		
		return result;
	}
	
}
