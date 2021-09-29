package com.gujerbit.encrypt.controller;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.util.Random;

import javax.servlet.http.HttpServletRequest;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@CrossOrigin("*")
@Controller
public class SHAController {
	
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
