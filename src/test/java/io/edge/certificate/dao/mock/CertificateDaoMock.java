package io.edge.certificate.dao.mock;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import io.edge.certificate.dao.CertificateDao;
import io.vertx.core.AsyncResult;
import io.vertx.core.Future;
import io.vertx.core.Handler;
import io.vertx.core.json.JsonObject;

public class CertificateDaoMock implements CertificateDao {

	private final Map<String, JsonObject> storage = new HashMap<>();

	@Override
	public void saveCertificate(String account, String name, JsonObject keys, String certificate, Handler<AsyncResult<Boolean>> resultHandler) {

		storage.put(account + "." + name, new JsonObject().put("keys", keys).put("certificate", certificate));

		resultHandler.handle(Future.succeededFuture(true));

	}

	@Override
	public void getAllCertificates(String account, Handler<AsyncResult<List<JsonObject>>> resultHandler) {

		resultHandler.handle(Future.succeededFuture(new ArrayList<>()));

	}

	@Override
	public void findCertificate(String account, String name, boolean loadKeys, Handler<AsyncResult<JsonObject>> resultHandler) {

		resultHandler.handle(Future.succeededFuture(this.storage.get(account + "." + name)));

	}

	@Override
	public void deleteCertificate(String account, String name, Handler<AsyncResult<Boolean>> resultHandler) {

		resultHandler.handle(Future.succeededFuture(this.storage.remove(account + "." + name) != null));

	}

}
