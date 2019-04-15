package io.edge.certificate.service.impl;

import java.security.KeyPair;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Date;

import io.edge.certificate.dao.CertificateDao;
import io.edge.certificate.service.CertificateService;
import io.edge.certificate.util.KeyGenerator;
import io.edge.certificate.util.KeyGenerator.Algorithm;
import io.vertx.core.AsyncResult;
import io.vertx.core.Future;
import io.vertx.core.Handler;
import io.vertx.core.json.JsonObject;

public class CertificateServiceImpl implements CertificateService {

	private final CertificateDao certificateDao;

	public CertificateServiceImpl(CertificateDao certificateDao) {
		super();
		this.certificateDao = certificateDao;
	}

	@Override
	public void createCertificate(String account, String name, String algorithm, JsonObject claims, Date notAfter, Handler<AsyncResult<JsonObject>> resultHandler) {

		Future<JsonObject> future = Future.future();

		try {
			KeyGenerator keyGen = KeyGenerator.create(Algorithm.valueOf(algorithm));

			KeyPair keyPair = keyGen.generateKeyPair();

			X509Certificate x509Certificate = keyGen.createCertificate(keyPair, claims.getString("commonName"), claims.getString("organization"), claims.getString("organizationalUnit"), Instant.now(), notAfter.toInstant());

			String privateKey = KeyGenerator.toPem(keyPair.getPrivate(), "PRIVATE KEY");

			String publicKey = KeyGenerator.toPem(keyPair.getPublic(), "PUBLIC KEY");

			String pem = KeyGenerator.toPem(x509Certificate, name);

			JsonObject certificate = new JsonObject()//
					.put("algorithm", algorithm) //
					.put("privateKey", privateKey)//
					.put("publicKey", publicKey)//
					.put("pem", pem);

			this.certificateDao.saveCertificate(account, name, certificate, ar -> {

				if (ar.succeeded()) {
					if (ar.result()) {
						future.complete(certificate);
					} else {
						future.fail("Certificate not saved");
					}
				} else {
					future.fail(ar.cause());
				}

			});

		} catch (Exception e) {
			future.fail(e);
		}

		future.setHandler(resultHandler);

	}
	
	@Override
	public void addCrertifivate(String account, String name, String certPEM, String privateKeyPEM, String publicKeyPEM, Handler<AsyncResult<Boolean>> resultHandler) {
		
		JsonObject certificate = new JsonObject()//
				.put("privateKey", privateKeyPEM)//
				.put("publicKey", publicKeyPEM)//
				.put("pem", certPEM);

		Future<Boolean> future = Future.future();
		
		this.certificateDao.saveCertificate(account, name, certificate, future);
		
		future.setHandler(resultHandler);
		
	}

	@Override
	public void createSignedCertificate(String account, String name, String algorithm, JsonObject claims, Date notAfter, String caCertName, Handler<AsyncResult<JsonObject>> resultHandler) {

		Future<JsonObject> future = Future.future();

		try {
			KeyGenerator keyGen = KeyGenerator.create(Algorithm.valueOf(algorithm));

			this.certificateDao.findCertificate(account, caCertName, ar -> {

				if (ar.succeeded()) {

					try {

						JsonObject caCertificate = ar.result();

						X509Certificate caCert = KeyGenerator.decodeCertificate(caCertificate.getString("pem"));

						KeyPair caKeyPair = keyGen.decodeKeyPair(caCertificate.getString("privateKey"), caCertificate.getString("publicKey"));

						KeyPair keyPair = keyGen.generateKeyPair();

						X509Certificate x509Certificate = keyGen.createSignedCertificate(caCert, caKeyPair, keyPair, claims.getString("commonName"), claims.getString("organization"), claims.getString("organizationalUnit"), Instant.now(), notAfter.toInstant());

						JsonObject certificate = new JsonObject()//
								.put("algorithm", algorithm) //
								.put("privateKey", KeyGenerator.toPem(keyPair.getPrivate(), "PRIVATE KEY"))//
								.put("publicKey", KeyGenerator.toPem(keyPair.getPublic(), "PUBLIC KEY"))//
								.put("pem", KeyGenerator.toPem(x509Certificate, name));

						this.certificateDao.saveCertificate(account, name, certificate, saveResult -> {

							if (saveResult.succeeded()) {
								if (saveResult.result()) {
									future.complete(certificate);
								} else {
									future.fail("Certificate not saved");
								}
							} else {
								future.fail(ar.cause());
							}

						});

					} catch (Exception e) {
						future.fail(e);
					}

				} else {
					future.fail(ar.cause());
				}

			});

		} catch (Exception e) {
			future.fail(e);
		}

		future.setHandler(resultHandler);

	}

	@Override
	public void verify(String account, String certName, Handler<AsyncResult<Boolean>> resultHandler) {

		Future<Boolean> future = Future.future();

		this.certificateDao.findCertificate(account, certName, ar -> {

			if (ar.succeeded()) {

				JsonObject certificate = ar.result();

				try {

					X509Certificate cert = KeyGenerator.decodeCertificate(certificate.getString("pem"));

					cert.checkValidity();
					future.complete(true);
				} catch (CertificateExpiredException
						| CertificateNotYetValidException e) {
					future.complete(false);
				} catch (Exception e) {
					future.fail(e);
				}

			} else {
				future.fail(ar.cause());
			}

		});

		future.setHandler(resultHandler);

	}

	@Override
	public void verify(String account, String certName, String caCertName, Handler<AsyncResult<Boolean>> resultHandler) {

		throw new UnsupportedOperationException("Not implemented yet");

	}

	@Override
	public void findCertificate(String account, String name, Handler<AsyncResult<JsonObject>> resultHandler) {

		this.certificateDao.findCertificate(account, name, resultHandler);

	}

	@Override
	public void deleteCertificate(String account, String name, Handler<AsyncResult<Boolean>> resultHandler) {

		this.certificateDao.deleteCertificate(account, name, resultHandler);

	}

}
