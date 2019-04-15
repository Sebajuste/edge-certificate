package io.edge.certificate.dao;

import java.util.List;

import io.vertx.core.AsyncResult;
import io.vertx.core.Handler;
import io.vertx.core.json.JsonObject;

public interface CertificateDao {

	void saveCertificate(String account, String name, JsonObject certificate, Handler<AsyncResult<Boolean>> resultHandler);

	void getAllCertificates(String account, Handler<AsyncResult<List<JsonObject>>> resultHandler);

	void findCertificate(String account, String name, Handler<AsyncResult<JsonObject>> resultHandler);

	void deleteCertificate(String account, String name, Handler<AsyncResult<Boolean>> resultHandler);

}
