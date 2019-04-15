package io.edge.certificate.util;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;

import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.PKCSException;
import org.junit.Test;

import io.edge.certificate.util.KeyGenerator.Algorithm;

public class KeyGeneratorTest {

	@Test
	public void genKeyPairTest() throws NoSuchAlgorithmException, NoSuchProviderException {

		KeyGenerator kg = KeyGenerator.create(Algorithm.ECDSA_SHA1);

		KeyPair kp = kg.generateKeyPair();

		assertNotNull(kp);

		kg = KeyGenerator.create(Algorithm.ECDSA_SHA256);

		kp = kg.generateKeyPair();

		assertNotNull(kp);

	}

	@Test
	public void genCertificateTest() throws InvalidKeyException, CertificateException, NoSuchAlgorithmException, NoSuchProviderException, OperatorCreationException, SignatureException {

		KeyGenerator keyGen = KeyGenerator.create(Algorithm.ECDSA_SHA1);

		KeyPair keyPair = keyGen.generateKeyPair();

		LocalDateTime notAfter = LocalDateTime.now().plusDays(365);

		X509Certificate cert = keyGen.createCertificate(keyPair, "intellipool.eu", "PENTAIR", "PENTAIR POOL & SAP", Instant.now(), notAfter.atZone(ZoneId.of("UTC")).toInstant());

		assertNotNull(cert);

		cert.checkValidity();

		cert.verify(keyPair.getPublic());
	}

	@Test(expected = CertificateExpiredException.class)
	public void validityCertTest() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, CertificateException, OperatorCreationException, SignatureException {

		KeyGenerator keyGen = KeyGenerator.create(Algorithm.ECDSA_SHA1);

		KeyPair keyPair = keyGen.generateKeyPair();

		LocalDateTime notBefore = LocalDateTime.now().minusDays(10);

		LocalDateTime notAfter = LocalDateTime.now().minusDays(5);

		X509Certificate cert = keyGen.createCertificate(keyPair, "intellipool.eu", "PENTAIR", "PENTAIR POOL & SAP", notBefore.atZone(ZoneId.of("UTC")).toInstant(), notAfter.atZone(ZoneId.of("UTC")).toInstant());

		assertNotNull(cert);

		cert.checkValidity();

		assertTrue(false); // Could not be reached

	}

	@Test
	public void createSignedCertificate() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, CertificateException, OperatorCreationException, SignatureException, PKCSException, IOException {

		KeyGenerator keyGen = KeyGenerator.create(Algorithm.ECDSA_SHA1);

		KeyPair caKeyPair = keyGen.generateKeyPair();

		LocalDateTime notAfter = LocalDateTime.now().plusDays(365);

		X509Certificate caCert = keyGen.createCertificate(caKeyPair, "intellipool.eu", "PENTAIR", "PENTAIR POOL & SAP", Instant.now(), notAfter.atZone(ZoneId.of("UTC")).toInstant());

		KeyPair keyPair = keyGen.generateKeyPair();

		X509Certificate cert = keyGen.createSignedCertificate(caCert, caKeyPair, keyPair, "myObject", "PENTAIR POOL & SAP", "IoT", Instant.now(), notAfter.atZone(ZoneId.of("UTC")).toInstant());

		assertNotNull(cert);

		cert.checkValidity();

		cert.verify(caKeyPair.getPublic());

	}

	@Test
	public void encodeDecodeKeyPair() throws NoSuchAlgorithmException, NoSuchProviderException, IOException, InvalidKeySpecException {

		KeyGenerator keyGen = KeyGenerator.create(Algorithm.ECDSA_SHA1);

		KeyPair keyPair = keyGen.generateKeyPair();

		
		String privateKey = KeyGenerator.toPem(keyPair.getPrivate(), "PRIVATE KEY");

		String publicKey = KeyGenerator.toPem(keyPair.getPublic(), "PUBLIC KEY");

		KeyPair keyPairDecoded = keyGen.decodeKeyPair(privateKey, publicKey);

		assertNotNull(keyPairDecoded);

	}

	@Test
	public void encodeDecodeCertificate() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, CertificateException, OperatorCreationException, SignatureException, IOException {

		KeyGenerator keyGen = KeyGenerator.create(Algorithm.ECDSA_SHA1);

		KeyPair keyPair = keyGen.generateKeyPair();

		LocalDateTime notAfter = LocalDateTime.now().plusDays(365);

		X509Certificate cert = keyGen.createCertificate(keyPair, "intellipool.eu", "PENTAIR", "PENTAIR POOL & SAP", Instant.now(), notAfter.atZone(ZoneId.of("UTC")).toInstant());

		String pemCert = KeyGenerator.toPem(cert, "test");

		X509Certificate certDecoded = KeyGenerator.decodeCertificate(pemCert);

		assertNotNull(certDecoded);
	}

}
