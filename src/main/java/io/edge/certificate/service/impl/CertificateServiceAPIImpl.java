package io.edge.certificate.service.impl;

import java.time.Instant;

import io.edge.certificate.service.CertificateService;
import io.edge.certificate.service.CertificateServiceAPI;
import io.vertx.core.AsyncResult;
import io.vertx.core.Handler;
import io.vertx.core.Promise;
import io.vertx.core.buffer.Buffer;
import io.vertx.core.json.JsonObject;
import io.vertx.core.logging.Logger;
import io.vertx.core.logging.LoggerFactory;
import io.vertx.ext.web.api.OperationRequest;
import io.vertx.ext.web.api.OperationResponse;

public class CertificateServiceAPIImpl implements CertificateServiceAPI {

	private static final Logger LOGGER = LoggerFactory.getLogger(CertificateServiceAPIImpl.class);

	private final CertificateService certificateService;

	public CertificateServiceAPIImpl(CertificateService certificateService) {
		super();
		this.certificateService = certificateService;
	}

	@Override
	public void getCertificate(String account, String name, OperationRequest context, Handler<AsyncResult<OperationResponse>> resultHandler) {

		Promise<OperationResponse> promise = Promise.promise();

		promise.future().setHandler(resultHandler);

		this.certificateService.findCertificate(account, name, false, ar -> {

			if (ar.succeeded()) {

				JsonObject certificate = ar.result();
				if (certificate != null) {
					promise.complete(OperationResponse.completedWithPlainText(Buffer.buffer(ar.result().getString("certificate"))));
				} else {
					promise.complete(new OperationResponse().setStatusCode(204));
				}
			} else {
				LOGGER.error(ar.cause());
				promise.complete(new OperationResponse().setStatusCode(500));
			}

		});

	}

	@Override
	public void generateCertificate(String account, String name, String algorithm, String commonName, long validity, boolean cA, boolean auth, String caCertName, JsonObject body, OperationRequest context, Handler<AsyncResult<OperationResponse>> resultHandler) {

		Promise<OperationResponse> promise = Promise.promise();

		promise.future().setHandler(resultHandler);

		Handler<AsyncResult<JsonObject>> createResultHandler = ar -> {
			if (ar.succeeded()) {
				promise.complete(OperationResponse.completedWithJson(ar.result()));
			} else {
				promise.complete(new OperationResponse().setStatusCode(500));
			}
		};
		
		try {

		JsonObject claims = new JsonObject();

		if (body != null) {
			claims.mergeIn(body);
		}

		claims.put("commonName", commonName);

		LOGGER.info("body : " + body);
		LOGGER.info("claims : " + claims);
		LOGGER.info("cA : " + cA);

		
		long notAfterTimestamp = Instant.now().getEpochSecond() + validity;
		
		JsonObject options = new JsonObject()//
				.put("ca", cA)//
				.put("auth", auth)//
				.put("notAfter", Instant.ofEpochSecond(notAfterTimestamp) );
		
		

		if (caCertName != null) {
			this.certificateService.createSignedCertificate(account, name, caCertName, algorithm, claims, options, createResultHandler);
		} else {
			this.certificateService.createCertificate(account, name, algorithm, claims, options, createResultHandler);
		}

		} catch(Exception e) {
			LOGGER.error(e);
			promise.complete(new OperationResponse().setStatusCode(500));
		}
		
	}

	@Override
	public void deleteCertificate(String account, String name, OperationRequest context, Handler<AsyncResult<OperationResponse>> resultHandler) {

		Promise<OperationResponse> promise = Promise.promise();

		promise.future().setHandler(resultHandler);

		this.certificateService.deleteCertificate(account, name, ar -> {
			if (ar.succeeded()) {
				promise.complete(new OperationResponse().setStatusCode(204));
			} else {
				promise.complete(new OperationResponse().setStatusCode(500));
			}
		});

	}

}
