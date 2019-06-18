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

		JsonObject claims = new JsonObject().put("commonName", "test");

		Async async = context.async();

		certService.createCertificate(ACCOUNT, "ca-cert-test", "RSA_SHA1", claims, notAfter, ar1 -> {

			if (ar1.succeeded()) {

				certService.createSignedCertificate(ACCOUNT, "cert-test", "RSA_SHA1", claims, notAfter, "ca-cert-test", ar2 -> {

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

}
