package io.edge.certificate.service.impl;

import java.time.Instant;

import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;

import io.edge.certificate.dao.mock.CertificateDaoMock;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.unit.Async;
import io.vertx.ext.unit.TestContext;
import io.vertx.ext.unit.junit.RunTestOnContext;
import io.vertx.ext.unit.junit.VertxUnitRunner;

@RunWith(VertxUnitRunner.class)
public class CertificateServiceImplTest {

	private static final String ACCOUNT = "test";

	@Rule
	public RunTestOnContext rule = new RunTestOnContext();

	private CertificateServiceImpl certService;

	@Before
	public void start() {

		certService = new CertificateServiceImpl(new CertificateDaoMock());

	}

	@After
	public void end() {

	}

	@Test
	public void verifyCertificateFromCATest(TestContext context) {

		long notAfter = Instant.now().getEpochSecond() + 600L;

		JsonObject caClaims = new JsonObject()//
				.put("commonName", "CA certificate")//
				.put("organization", "Edge")//
				.put("organizationalUnit", "IoT");

		JsonObject caOptions = new JsonObject()//
				.put("ca", true).put("notAfter", Instant.ofEpochSecond(notAfter));

		Async async = context.async();

		certService.createCertificate(ACCOUNT, "ca-cert-test", "RSA_SHA1", caClaims, caOptions, ar1 -> {

			if (ar1.succeeded()) {

				JsonObject serverClaims = new JsonObject()//
						.put("commonName", "MQTT Server")//
						.put("organization", "Edge")//
						.put("organizationalUnit", "IoT");

				JsonObject oserverOtions = new JsonObject()//
						.put("notAfter", Instant.ofEpochSecond(notAfter));

				certService.createSignedCertificate(ACCOUNT, "cert-test", "ca-cert-test", "RSA_SHA1", serverClaims, oserverOtions, ar2 -> {

					if (ar2.succeeded()) {

						certService.verifyCertificateFromCA(ACCOUNT, "cert-test", "ca-cert-test", ar3 -> {

							if (ar3.succeeded()) {

								context.assertTrue(ar3.result());

								async.complete();

							} else {
								context.fail(ar3.cause());
							}

						});

					} else {
						context.fail(ar2.cause());
					}

				});

			} else {
				context.fail(ar1.cause());
			}

		});

	}

	@Test
	public void verifyCertificateTest(TestContext context) {

		JsonObject claims = new JsonObject().put("commonName", "test");

		long notAfterTimestamp = Instant.now().getEpochSecond() + 600L;

		JsonObject options = new JsonObject().put("notAfter", Instant.ofEpochSecond(notAfterTimestamp));

		Async async = context.async();

		certService.createCertificate(ACCOUNT, "cert-test", "RSA_SHA1", claims, options, ar1 -> {

			if (ar1.succeeded()) {

				certService.verifyCertificate(ACCOUNT, "cert-test", ar2 -> {

					if (ar2.succeeded()) {

						context.assertTrue(ar2.result());

						async.complete();

					} else {
						context.fail(ar2.cause());
					}

				});

			} else {
				context.fail(ar1.cause());
			}

		});

	}

}
