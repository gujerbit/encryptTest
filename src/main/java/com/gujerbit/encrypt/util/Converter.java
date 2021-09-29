package com.gujerbit.encrypt.util;

import org.springframework.stereotype.Component;

@Component
public class Converter {
	
	public String byteToHex(byte[] value) {
		StringBuffer sb = new StringBuffer(value.length * 2);
		String hex = "";
		
		for(int i = 0; i < value.length; i++) {
			hex = "0" + Integer.toHexString(0xff & value[i]);
			sb.append(hex.substring(hex.length() - 2));
		}
		
		return sb.toString();
	}
	
	public byte[] hexToByte(String value) {
		byte[] result = new byte[value.length() / 2];
		
		for(int i = 0; i < result.length; i++) result[i] = (byte) Integer.parseInt(value.substring(2 * i, 2 * i + 2), 16);
		
		return result;
	}

}
