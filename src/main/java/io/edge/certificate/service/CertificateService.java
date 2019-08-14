package io.edge.certificate.service;

import io.vertx.codegen.annotations.ProxyGen;
import io.vertx.codegen.annotations.VertxGen;
import io.vertx.core.AsyncResult;
import io.vertx.core.Handler;
import io.vertx.core.json.JsonObject;

@ProxyGen
@VertxGen
public interface CertificateService {

	static final String ADDRESS = "edge.certificate.service";

	void createCertificate(String account, String name, String algorithm, JsonObject claims, JsonObject options, Handler<AsyncResult<JsonObject>> resultHandler);

	void addCrertificate(String account, String name, String certPEM, String privateKeyPEM, String publicKeyPEM, Handler<AsyncResult<Boolean>> resultHandler);

	void createSignedCertificate(String account, String name, String caCertName, String algorithm, JsonObject claims, JsonObject options, Handler<AsyncResult<JsonObject>> resultHandler);

	void verifyCertificate(String account, String certName, Handler<AsyncResult<Boolean>> resultHandler);

	void verifyCertificateFromCA(String account, String certName, String caCertName, Handler<AsyncResult<Boolean>> resultHandler);

	void findCertificate(String account, String name, boolean loadKeys, Handler<AsyncResult<JsonObject>> resultHandler);

	void deleteCertificate(String account, String name, Handler<AsyncResult<Boolean>> resultHandler);

}
