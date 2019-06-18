package io.edge.certificate.service.impl;

import io.edge.certificate.service.CertificateService;
import io.edge.certificate.service.CertificateServiceAPI;
import io.vertx.core.AsyncResult;
import io.vertx.core.Future;
import io.vertx.core.Handler;
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

		Future<OperationResponse> future = Future.future();

		future.setHandler(resultHandler);

		this.certificateService.findCertificate(account, name, false, ar -> {

			if (ar.succeeded()) {

				JsonObject certificate = ar.result();
				if (certificate != null) {
					future.complete(OperationResponse.completedWithPlainText(Buffer.buffer(ar.result().getString("certificate"))));
				} else {
					future.complete(new OperationResponse().setStatusCode(204));
				}
			} else {
				LOGGER.error(ar.cause());
				future.complete(new OperationResponse().setStatusCode(500));
			}

		});

	}

	@Override
	public void generateCertificate(String account, String name, String algorithm, String commonName, long notAfterTimestamp, String organization, String organizationalUnit, String caCertName, OperationRequest context, Handler<AsyncResult<OperationResponse>> resultHandler) {

		Future<OperationResponse> future = Future.future();

		future.setHandler(resultHandler);

		JsonObject claims = new JsonObject()//
				.put("commonName", commonName)//
				.put("organization", organization)//
				.put("organizationalUnit", organizationalUnit);

		Handler<AsyncResult<JsonObject>> createResultHandler = ar -> {
			if (ar.succeeded()) {
				future.complete(OperationResponse.completedWithJson(ar.result()));
			} else {
				future.complete(new OperationResponse().setStatusCode(500));
			}
		};

		if (caCertName != null) {
			this.certificateService.createSignedCertificate(account, name, algorithm, claims, notAfterTimestamp, caCertName, createResultHandler);
		} else {
			this.certificateService.createCertificate(account, name, algorithm, claims, notAfterTimestamp, createResultHandler);
		}

	}

	@Override
	public void deleteCertificate(String account, String name, OperationRequest context, Handler<AsyncResult<OperationResponse>> resultHandler) {

		Future<OperationResponse> future = Future.future();

		future.setHandler(resultHandler);

		this.certificateService.deleteCertificate(account, name, ar -> {
			if (ar.succeeded()) {
				future.complete(new OperationResponse().setStatusCode(204));
			} else {
				future.complete(new OperationResponse().setStatusCode(500));
			}
		});

	}

}
