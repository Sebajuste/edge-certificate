package io.edge.certificate.util;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;
import java.util.Date;
import java.util.Objects;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jcajce.provider.asymmetric.x509.CertificateFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.jcajce.JcaMiscPEMGenerator;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCSException;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemObjectGenerator;
import org.bouncycastle.util.io.pem.PemReader;
import org.bouncycastle.util.io.pem.PemWriter;

public class KeyGenerator {

	static {
		Security.addProvider(new BouncyCastleProvider());
	}

	public static enum Algorithm {

		RSA_SHA128("RSA", "SHA128withRSA", 1024),
		RSA_SHA256("RSA", "SHA256withRSA", 1024),
		ECDSA_SHA256("ECDSA", "SHA256withECDSA", 256),
		ECDSA_SHA1("ECDSA", "SHA1withECDSA", 256);

		private final String algo;
		private final String signature; 
		private final int size;

		Algorithm(String algo, String signature, int size) {
			this.algo = algo;
			this.signature = signature;
			this.size = size;
		}

		public String toString() {
			return "algo=" + this.algo + ", signature=" + signature + ", size=" + size;
		}

	}

	public static class PemFile {

		private PemObjectGenerator pemObject;

		public PemFile(Key key, String description) {
			this.pemObject = new PemObject(description, key.getEncoded());
		}

		public PemFile(Certificate cert, String description) throws CertificateEncodingException, IOException {
			this.pemObject = new JcaMiscPEMGenerator(cert);
		}

		public void write(OutputStream out) throws IOException {

			PemWriter pemWriter = new PemWriter(new OutputStreamWriter(out));
			try {
				pemWriter.writeObject(this.pemObject);
			} finally {
				pemWriter.close();
			}

		}
	}

	private final Algorithm algorithm;

	private KeyGenerator(Algorithm algorithm) {
		super();
		this.algorithm = algorithm;
	}

	public static KeyGenerator create(Algorithm algorithm) {
		return new KeyGenerator(algorithm);
	}

	public KeyPair decodeKeyPair(String privateBase64, String publicBase64) throws IOException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException {

		PemReader parser = new PemReader(new InputStreamReader(new ByteArrayInputStream(privateBase64.getBytes()), "UTF-8"));

		PemObject obj = parser.readPemObject();

		parser.close();

		byte[] content = obj.getContent();

		PKCS8EncodedKeySpec privKeySpec = new PKCS8EncodedKeySpec(content);

		KeyFactory factory = KeyFactory.getInstance(this.algorithm.algo, "BC");

		PrivateKey privateKey = factory.generatePrivate(privKeySpec);

		parser = new PemReader(new InputStreamReader(new ByteArrayInputStream(publicBase64.getBytes()), "UTF-8"));

		obj = parser.readPemObject();

		parser.close();

		content = obj.getContent();

		X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(content);

		PublicKey publicKey = factory.generatePublic(pubKeySpec);

		return new KeyPair(publicKey, privateKey);
	}

	public static X509Certificate decodeCertificate(String certBase64) throws CertificateException {
		return (X509Certificate) new CertificateFactory().engineGenerateCertificate(new ByteArrayInputStream(certBase64.getBytes()));
	}

	public static String toPem(Key key, String description) throws IOException {

		Objects.requireNonNull(key);
		Objects.requireNonNull(description);

		if (description.trim().length() == 0) {
			throw new InvalidParameterException("Invalid description");
		}

		ByteArrayOutputStream out = new ByteArrayOutputStream();
		new PemFile(key, description).write(out);
		return out.toString();
	}

	public static String toPem(Certificate cert, String description) throws IOException, CertificateEncodingException {
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		new PemFile(cert, description).write(out);
		return out.toString();
	}

	public KeyPair generateKeyPair(String randomAlgo) throws NoSuchAlgorithmException, NoSuchProviderException {

		KeyPairGenerator generator = KeyPairGenerator.getInstance(this.algorithm.algo);
		
		SecureRandom random = SecureRandom.getInstance(randomAlgo != null ? randomAlgo : "SHA1PRNG");

		generator.initialize(this.algorithm.size, random);

		KeyPair keyPair = generator.generateKeyPair();

		return keyPair;
	}
	
	public KeyPair generateKeyPair() throws NoSuchAlgorithmException, NoSuchProviderException {
		return this.generateKeyPair(null);
	}

	public X509Certificate createCertificate(KeyPair keyPair, String commonName, String organization, String organizationalUnitName, Date notBefore, Date notAfter) throws CertificateException, NoSuchAlgorithmException, NoSuchProviderException, OperatorCreationException, InvalidKeyException, SignatureException {

		Objects.requireNonNull(keyPair);
		Objects.requireNonNull(commonName);
		Objects.requireNonNull(notBefore);
		Objects.requireNonNull(notAfter);

		X500NameBuilder nameBuilder = new X500NameBuilder(BCStyle.INSTANCE);
		nameBuilder.addRDN(BCStyle.CN, commonName);
		if (organization != null) {
			nameBuilder.addRDN(BCStyle.O, organization);
		}
		if (organizationalUnitName != null) {
			nameBuilder.addRDN(BCStyle.OU, organizationalUnitName);
		}
		
		X500Name issuer = nameBuilder.build();

		// SecureRandom secureRandom = SecureRandom.getInstanceStrong();

		BigInteger serial = new BigInteger(64, new SecureRandom());
		
		X509v3CertificateBuilder certGen = new JcaX509v3CertificateBuilder(issuer, serial, notBefore, notAfter, issuer, keyPair.getPublic());

		X509CertificateHolder certHldr = certGen.build(new JcaContentSignerBuilder(this.algorithm.signature).setProvider("BC").build(keyPair.getPrivate()));

		X509Certificate cert = new JcaX509CertificateConverter().setProvider("BC").getCertificate(certHldr);

		cert.checkValidity(new Date());

		cert.verify(keyPair.getPublic());

		return cert;

	}

	public X509Certificate createCertificate(KeyPair keyPair, String commonName, String organization, String organizationalUnitName, Instant notBefore, Instant notAfter) throws CertificateException, NoSuchAlgorithmException, NoSuchProviderException, OperatorCreationException, InvalidKeyException, SignatureException {
		return createCertificate(keyPair, commonName, organization, organizationalUnitName, Date.from(notBefore), Date.from(notAfter));
	}

	public X509Certificate createSignedCertificate(X509Certificate caCert, KeyPair caKeyPair, KeyPair keyPair, String commonName, String organization, String organizationalUnitName, Date notBefore, Date notAfter) throws OperatorCreationException, PKCSException, NoSuchAlgorithmException, NoSuchProviderException, IOException, CertificateException {

		Objects.requireNonNull(caCert);
		Objects.requireNonNull(caKeyPair);
		Objects.requireNonNull(commonName);
		Objects.requireNonNull(notBefore);
		Objects.requireNonNull(notAfter);

		X500NameBuilder nameBuilder = new X500NameBuilder(BCStyle.INSTANCE);
		nameBuilder.addRDN(BCStyle.CN, commonName);
		if (organization != null) {
			nameBuilder.addRDN(BCStyle.O, organization);
		}
		if (organizationalUnitName != null) {
			nameBuilder.addRDN(BCStyle.OU, organizationalUnitName);
		}

		X500Name issuer = nameBuilder.build();

		// KeyPair keyPair = generateKeyPair();

		JcaPKCS10CertificationRequestBuilder requestBuilder = new JcaPKCS10CertificationRequestBuilder(issuer, keyPair.getPublic());

		PKCS10CertificationRequest csr = requestBuilder.build(new JcaContentSignerBuilder(this.algorithm.signature).setProvider("BC").build(keyPair.getPrivate()));

		if (!csr.isSignatureValid(new JcaContentVerifierProviderBuilder().setProvider("BC").build(keyPair.getPublic()))) {
			throw new CertificateException("Failed verify check");
		}

		X500Name caissuer = new X500Name(caCert.getSubjectX500Principal().getName());
		BigInteger serial = new BigInteger(32, new SecureRandom());

		X509v3CertificateBuilder certGen = new X509v3CertificateBuilder(caissuer, serial, notBefore, notAfter, csr.getSubject(), csr.getSubjectPublicKeyInfo());

		JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();
		certGen.addExtension(Extension.authorityKeyIdentifier, false, extUtils.createAuthorityKeyIdentifier(caCert)).addExtension(Extension.subjectKeyIdentifier, false, extUtils.createSubjectKeyIdentifier(keyPair.getPublic())).addExtension(Extension.basicConstraints, true, new BasicConstraints(0)).addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment)).addExtension(Extension.extendedKeyUsage, true, new ExtendedKeyUsage(KeyPurposeId.id_kp_serverAuth));

		X509CertificateHolder certHldr = certGen.build(new JcaContentSignerBuilder(this.algorithm.signature).setProvider("BC").build(caKeyPair.getPrivate()));

		return new JcaX509CertificateConverter().setProvider("BC").getCertificate(certHldr);

	}

	public X509Certificate createSignedCertificate(X509Certificate caCert, KeyPair caKeyPair, KeyPair keyPair, String commonName, String organization, String organizationalUnitName, Instant notBefore, Instant notAfter) throws OperatorCreationException, NoSuchAlgorithmException, NoSuchProviderException, CertificateException, PKCSException, IOException {
		return this.createSignedCertificate(caCert, caKeyPair, keyPair, commonName, organization, organizationalUnitName, Date.from(notBefore), Date.from(notAfter));
	}

}
