package io.edge.certificate.service.impl;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.time.Instant;

import io.edge.certificate.dao.CertificateDao;
import io.edge.certificate.service.CertificateService;
import io.edge.certificate.util.KeyGenerator;
import io.edge.certificate.util.KeyGenerator.Algorithm;
import io.vertx.core.AsyncResult;
import io.vertx.core.CompositeFuture;
import io.vertx.core.Future;
import io.vertx.core.Handler;
import io.vertx.core.json.JsonObject;
import io.vertx.core.logging.Logger;
import io.vertx.core.logging.LoggerFactory;

public class CertificateServiceImpl implements CertificateService {

	private static final Logger LOGGER = LoggerFactory.getLogger(CertificateServiceImpl.class);

	private final CertificateDao certificateDao;

	public CertificateServiceImpl(CertificateDao certificateDao) {
		super();
		this.certificateDao = certificateDao;
	}

	@Override
	public void createCertificate(String account, String name, String algorithm, JsonObject claims, long notAfterTimestamp, Handler<AsyncResult<JsonObject>> resultHandler) {

		Future<JsonObject> future = Future.future();

		future.setHandler(resultHandler);

		try {
			KeyGenerator keyGen = KeyGenerator.create(Algorithm.valueOf(algorithm));

			KeyPair keyPair = keyGen.generateKeyPair();

			X509Certificate x509Certificate = keyGen.createCertificate(keyPair, claims.getString("commonName"), claims.getString("organization"), claims.getString("organizationalUnit"), Instant.now(), Instant.ofEpochSecond(notAfterTimestamp));

			JsonObject keys = new JsonObject()//
					.put("algorithm", algorithm) //
					.put("private", KeyGenerator.toPem(keyPair.getPrivate(), "PRIVATE KEY"))//
					.put("public", KeyGenerator.toPem(keyPair.getPublic(), "PUBLIC KEY"));

			String cert = KeyGenerator.toPem(x509Certificate, name);

			this.certificateDao.saveCertificate(account, name, keys, cert, ar -> {

				if (ar.succeeded()) {

					JsonObject certificate = new JsonObject()//
							.put("keys", keys)//
							.put("certificate", cert);

					future.complete(certificate);
				} else {
					future.fail(ar.cause());
				}

			});

		} catch (Exception e) {
			LOGGER.error("Unknown error : ", e);
			future.fail(e);
		}

	}

	@Override
	public void addCrertificate(String account, String name, String certPEM, String privateKeyPEM, String publicKeyPEM, Handler<AsyncResult<Boolean>> resultHandler) {

		Future<Boolean> future = Future.future();

		future.setHandler(resultHandler);

		JsonObject keys = new JsonObject().put("private", privateKeyPEM).put("public", publicKeyPEM);

		this.certificateDao.saveCertificate(account, name, keys, certPEM, future);

	}

	@Override
	public void createSignedCertificate(String account, String name, String algorithm, JsonObject claims, long notAfterTimestamp, String caCertName, Handler<AsyncResult<JsonObject>> resultHandler) {

		LOGGER.info("createSignedCertificate");

		Future<JsonObject> future = Future.future();

		try {
			KeyGenerator keyGen = KeyGenerator.create(Algorithm.valueOf(algorithm));

			this.certificateDao.findCertificate(account, caCertName, true, ar -> {

				if (ar.succeeded()) {

					try {

						JsonObject caCertificate = ar.result();
						
						JsonObject caKeys = caCertificate.getJsonObject("keys");

						X509Certificate caCert = KeyGenerator.decodeCertificate(caCertificate.getString("certificate"));

						KeyPair caKeyPair = keyGen.decodeKeyPair(caKeys.getString("private"), caKeys.getString("public"));

						KeyPair keyPair = keyGen.generateKeyPair();

						X509Certificate x509Certificate = keyGen.createSignedCertificate(caCert, caKeyPair, keyPair, claims.getString("commonName"), claims.getString("organization"), claims.getString("organizationalUnit"), Instant.now(), Instant.ofEpochSecond(notAfterTimestamp));

						JsonObject keys = new JsonObject()//
								.put("algorithm", algorithm) //
								.put("private", KeyGenerator.toPem(keyPair.getPrivate(), "PRIVATE KEY"))//
								.put("public", KeyGenerator.toPem(keyPair.getPublic(), "PUBLIC KEY"));

						String cert = KeyGenerator.toPem(x509Certificate, name);

						this.certificateDao.saveCertificate(account, name, keys, cert, saveResult -> {

							if (saveResult.succeeded()) {

								JsonObject certificate = new JsonObject()//
										.put("keys", keys)//
										.put("certificate", cert);

								future.complete(certificate);
							} else {
								LOGGER.error(ar.cause());
								future.fail(ar.cause());
							}

						});

					} catch (Exception e) {
						LOGGER.error(ar.cause());
						future.fail(e);
					}

				} else {
					LOGGER.error(ar.cause());
					future.fail(ar.cause());
				}

			});

		} catch (Exception e) {
			LOGGER.error("Invalid algorithm : " + e.getMessage(), e);
			future.fail(e);
		}

		future.setHandler(resultHandler);

	}

	@Override
	public void verifyCertificate(String account, String certName, Handler<AsyncResult<Boolean>> resultHandler) {

		Future<Boolean> future = Future.future();

		this.certificateDao.findCertificate(account, certName, false, ar -> {

			if (ar.succeeded()) {

				JsonObject certificate = ar.result();

				try {

					X509Certificate cert = KeyGenerator.decodeCertificate(certificate.getString("certificate"));

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
	public void verifyCertificateFromCA(String account, String certName, String caCertName, Handler<AsyncResult<Boolean>> resultHandler) {

		Future<JsonObject> certFuture = Future.future();
		this.certificateDao.findCertificate(account, certName, false, certFuture);

		Future<JsonObject> caCertFuture = Future.future();
		this.certificateDao.findCertificate(account, caCertName, true, caCertFuture);

		Future<Boolean> future = Future.future();

		CompositeFuture.all(certFuture, caCertFuture).setHandler(ar -> {

			if (ar.succeeded()) {

				CompositeFuture cf = ar.result();

				JsonObject certificate = cf.resultAt(0);

				JsonObject caCertificate = cf.resultAt(1);

				try {
					
					JsonObject caKeys = caCertificate.getJsonObject("keys");
					
					X509Certificate cert = KeyGenerator.decodeCertificate(certificate.getString("certificate"));

					KeyGenerator keyGen = KeyGenerator.create(Algorithm.valueOf(caKeys.getString("algorithm")));

					KeyPair caKeyPair = keyGen.decodeKeyPair(caKeys.getString("private"), caKeys.getString("public"));

					cert.verify(caKeyPair.getPublic());

					cert.checkValidity();

					future.complete(true);

				} catch (InvalidKeyException | SignatureException e) {
					future.complete(false);
				} catch (CertificateExpiredException
						| CertificateNotYetValidException e) {
					future.complete(false);
				} catch (CertificateException | NoSuchAlgorithmException
						| NoSuchProviderException | InvalidKeySpecException
						| IOException e) {
					future.fail(e);
				}

			} else {
				future.fail(ar.cause());
			}

		});

		future.setHandler(resultHandler);

	}

	@Override
	public void findCertificate(String account, String name, boolean loadKeys, Handler<AsyncResult<JsonObject>> resultHandler) {

		this.certificateDao.findCertificate(account, name, loadKeys, resultHandler);

	}

	@Override
	public void deleteCertificate(String account, String name, Handler<AsyncResult<Boolean>> resultHandler) {

		this.certificateDao.deleteCertificate(account, name, resultHandler);

	}

}
