package io.edge.certificate.service;

import io.vertx.core.AsyncResult;
import io.vertx.core.Handler;
import io.vertx.ext.web.api.OperationRequest;
import io.vertx.ext.web.api.OperationResponse;
import io.vertx.ext.web.api.generator.WebApiServiceGen;

@WebApiServiceGen
public interface CertificateServiceAPI {

	static final String ADDRESS = "edge.certificates.service-api";
	
	void getCertificate(String account, String name, OperationRequest context, Handler<AsyncResult<OperationResponse>> resultHandler);

	void generateCertificate(String account, String name, String algorithm, String commonName, long notAfterTimestamp, String organization, String organizationalUnit, String caCertName, OperationRequest context, Handler<AsyncResult<OperationResponse>> resultHandler);

	void deleteCertificate(String account, String name, OperationRequest context, Handler<AsyncResult<OperationResponse>> resultHandler);

}