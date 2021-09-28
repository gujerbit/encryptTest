package com.gujerbit.encrypt.controller;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.util.Base64;

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
	
	private final String IV = "iloveprogramming";

	@GetMapping("/encrypt/SHA-224")
	public @ResponseBody String encryptSHA224(HttpServletRequest req) {
		try {
			String value = req.getParameter("param");
			MessageDigest md = MessageDigest.getInstance("SHA-224");
			byte[] messageDigest = md.digest(value.getBytes());
			BigInteger bi = new BigInteger(1, messageDigest);
			String hashText = bi.toString(16);
			
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
			md.update(value.getBytes());
			
			return String.format("%064x", new BigInteger(1, md.digest()));
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
			md.update(value.getBytes());
			byte[] messageDigest = md.digest();
			
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
			md.update(value.getBytes());
			
			return String.format("%0128x", new BigInteger(1, md.digest()));
		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}
	}
	
	@GetMapping("/encrypt/AES-CBC")
	public @ResponseBody String encryptAESCBC(HttpServletRequest req) {
		try {
			String value = req.getParameter("param");
			Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			SecretKeySpec ss = new SecretKeySpec(IV.getBytes(), "AES");
			IvParameterSpec ips = new IvParameterSpec(IV.getBytes());
			cipher.init(Cipher.ENCRYPT_MODE, ss, ips);
			byte[] encrypt = cipher.doFinal(value.getBytes());
			
			return new String(Base64.getEncoder().encode(encrypt));
		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}
	}
	
	@GetMapping("/decrypt/AES-CBC")
	public @ResponseBody String decryptAESCBC(HttpServletRequest req) {
		try {
			String value = req.getParameter("param");
			Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			SecretKeySpec ss = new SecretKeySpec(IV.getBytes(), "AES");
			IvParameterSpec ips = new IvParameterSpec(IV.getBytes());
			cipher.init(Cipher.DECRYPT_MODE, ss, ips);
			byte[] decryptByte = Base64.getDecoder().decode(value.getBytes());
			byte[] decrypt = cipher.doFinal(decryptByte);
			
			return new String(decrypt);
		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}
	}
	
	@GetMapping("/encrypt/AES-GCM")
	public @ResponseBody String encryptAESGCM(HttpServletRequest req) {
		try {
			String value = req.getParameter("param");
			Cipher cipher = Cipher.getInstance("AES/GCM/PKCS5Padding");
			SecretKeySpec ss = new SecretKeySpec(IV.getBytes(), "AES");
			GCMParameterSpec gps = new GCMParameterSpec(128, IV.getBytes());
			cipher.init(Cipher.ENCRYPT_MODE, ss, gps);
			byte[] encrypt = cipher.doFinal(value.getBytes());
			
			return new String(Base64.getEncoder().encode(encrypt));
		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}
	}
	
	@GetMapping("/decrypt/AES-GCM")
	public @ResponseBody String decryptAESGCM(HttpServletRequest req) {
		try {
			String value = req.getParameter("param");
			Cipher cipher = Cipher.getInstance("AES/GCM/PKCS5Padding");
			SecretKeySpec ss = new SecretKeySpec(IV.getBytes(), "AES");
			GCMParameterSpec gps = new GCMParameterSpec(128, IV.getBytes());
			cipher.init(Cipher.DECRYPT_MODE, ss, gps);
			byte[] decryptByte = Base64.getDecoder().decode(value.getBytes());
			byte[] decrypt = cipher.doFinal(decryptByte);
			
			return new String(decrypt);
		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}
	}
	
}
