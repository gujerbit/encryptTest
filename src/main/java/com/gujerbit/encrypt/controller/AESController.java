package com.gujerbit.encrypt.controller;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.servlet.http.HttpServletRequest;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import com.gujerbit.encrypt.util.Converter;

@CrossOrigin("*")
@Controller
public class AESController {
	
	@Autowired
	private Converter converter;
	
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
			
			return converter.byteToHex(encrypt); //16진수로 변환
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
			byte[] decrypt = cipher.doFinal(converter.hexToByte(value));
			
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
			
			return converter.byteToHex(encrypt);
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
			byte[] decrypt = cipher.doFinal(converter.hexToByte(value));
			
			return new String(decrypt);
		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}
	}

}
