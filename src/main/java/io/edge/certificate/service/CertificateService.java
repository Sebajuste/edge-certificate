package io.edge.certificate.service;

import java.util.Date;

import io.vertx.codegen.annotations.VertxGen;
import io.vertx.core.AsyncResult;
import io.vertx.core.Handler;
import io.vertx.core.json.JsonObject;

@VertxGen
public interface CertificateService {
	
	static final String ADDRESS = "edge.certificate.service";

	void createCertificate(String account, String name, String algorithm, JsonObject claims, Date notAfter, Handler<AsyncResult<JsonObject>> resultHandler);
	
	void addCrertifivate(String account, String name, String certPEM, String privateKeyPEM, String publicKeyPEM, Handler<AsyncResult<Boolean>> resultHandler);
	
	void createSignedCertificate(String account, String name, String algorithm, JsonObject claims, Date notAfter, String caCertName, Handler<AsyncResult<JsonObject>> resultHandler);

	void verify(String account, String certName, Handler<AsyncResult<Boolean>> resultHandler);
	
	void verify(String account, String certName, String caCertName, Handler<AsyncResult<Boolean>> resultHandler);
	
	void findCertificate(String account, String name, Handler<AsyncResult<JsonObject>> resultHandler);

	void deleteCertificate(String account, String name, Handler<AsyncResult<Boolean>> resultHandler);

}
