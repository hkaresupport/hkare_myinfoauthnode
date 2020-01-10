package com.hkare.openam.auth.nodes.util;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.Random;

import org.apache.commons.lang.RandomStringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;

public class MyInfoCryptoUtil {

	private static final Logger logger = LoggerFactory.getLogger("amAuth");

	/**
	 * @param accessToken
	 * @param keyStoreLocation
	 * @param password
	 * @param keyAlias
	 * @return
	 */
	public static String validateAccessToken(String accessToken, String keyStoreLocation, String password,
			String keyAlias) {
		String subject = null;
		logger.debug("validateAccessToken :" + accessToken);
		logger.debug("keyStoreLocation :" + keyStoreLocation);
		logger.debug("password :" + password);
		logger.debug("keyAlias :" + keyAlias);
		try {
			Claims claims = Jwts.parser().setSigningKey(getPublicKey(keyStoreLocation, password, keyAlias))
					.parseClaimsJws(accessToken).getBody();
			subject = claims.getSubject();
			logger.debug("calims subject from jws:" + subject);
		} catch (Exception e) {
			logger.error("Error while validating the jwt token:", e);
		}

		return subject;
	}

	public static PublicKey getPublicKey(String keyStoreLocation, String password, String keyAlias)
			throws InvalidKeySpecException, IOException, NoSuchAlgorithmException, KeyStoreException,
			CertificateException, UnrecoverableKeyException {

		// initialize keystore location
		FileInputStream inputStream = new FileInputStream(keyStoreLocation);

		KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
		keystore.load(inputStream, password.toCharArray());

		PublicKey publicKey = null;
		// Get certificate of public key
		Certificate cert = keystore.getCertificate(keyAlias);

		// Get public key
		publicKey = cert.getPublicKey();

		// Return a key
		return publicKey;
	}

	/**
	 * @return
	 * @throws NoSuchAlgorithmException
	 */
	public static String nonce() throws NoSuchAlgorithmException {
		Random rand = SecureRandom.getInstance("SHA1PRNG");

		return RandomStringUtils.randomNumeric(15);
	}

	/**
	 * @param data
	 * @param keyFile
	 * @return
	 * @throws InvalidKeyException
	 * @throws Exception
	 */
	public static String signRequest(String data, String keyFile) throws InvalidKeyException, Exception {
		// RSA-SHA256
		Signature rsa = Signature.getInstance("SHA256withRSA");
		rsa.initSign(getPrivate(keyFile));
		rsa.update(data.getBytes("UTF-8"));
		byte[] signedData = rsa.sign();

		String finalStr = Base64.getEncoder().encodeToString(signedData);
		return finalStr;
	}

	// Method to retrieve the Private Key from a file
	/**
	 * @param filename
	 * @return
	 * @throws Exception
	 */
	public static PrivateKey getPrivate(String filename) throws Exception {
		byte[] keyBytes = Files.readAllBytes(new File(filename).toPath());
		String privateKey = new String(keyBytes, "UTF-8");
		privateKey = privateKey.replaceAll("(-+BEGIN PRIVATE KEY-+\\r?\\n|-+END PRIVATE KEY-+\\r?\\n?)", "");

		// don't use this for real projects!

		keyBytes = Base64.getMimeDecoder().decode(privateKey.getBytes(StandardCharsets.US_ASCII));

		PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
		KeyFactory kf = KeyFactory.getInstance("RSA");
		return kf.generatePrivate(spec);
	}

}
