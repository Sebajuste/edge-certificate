package io.edge.certificate.dao.mongo;

import java.util.List;

import io.edge.certificate.dao.CertificateDao;
import io.vertx.core.AsyncResult;
import io.vertx.core.Future;
import io.vertx.core.Handler;
import io.vertx.core.Vertx;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.mongo.MongoClient;
import io.vertx.ext.mongo.UpdateOptions;

public class CertificateDaoMongo implements CertificateDao {

	private static final String COLLECTION_NAME = "certificates";

	private final MongoClient mongoClient;

	public CertificateDaoMongo(final Vertx vertx, final MongoClient mongoClient) {
		this.mongoClient = mongoClient;
	}

	@Override
	public void saveCertificate(String account, String name, JsonObject certificate, Handler<AsyncResult<Boolean>> resultHandler) {

		JsonObject query = new JsonObject()//
				.put("account", account)//
				.put("name", account);

		JsonObject update = new JsonObject()//
				.put("$set", new JsonObject().put("certificate", certificate));

		UpdateOptions options = new UpdateOptions();
		options.setUpsert(true);

		Future<Boolean> future = Future.future();

		this.mongoClient.updateCollectionWithOptions(CertificateDaoMongo.COLLECTION_NAME, query, update, options, ar -> {

			if (ar.succeeded()) {
				future.complete(ar.result().getDocModified() > 0);
			} else {
				future.fail(ar.cause());
			}

		});

		future.setHandler(resultHandler);

	}

	@Override
	public void getAllCertificates(String account, Handler<AsyncResult<List<JsonObject>>> resultHandler) {

		JsonObject query = new JsonObject().put("account", account);

		Future<List<JsonObject>> future = Future.future();

		this.mongoClient.find(COLLECTION_NAME, query, future);

		future.setHandler(resultHandler);
	}

	@Override
	public void findCertificate(String account, String name, Handler<AsyncResult<JsonObject>> resultHandler) {

		JsonObject query = new JsonObject()//
				.put("account", account)//
				.put("name", name);

		JsonObject fields = new JsonObject()//
				.put("certificate", 1);

		Future<JsonObject> future = Future.future();

		this.mongoClient.findOne(COLLECTION_NAME, query, fields, future);

		future.setHandler(resultHandler);
	}

	@Override
	public void deleteCertificate(String account, String name, Handler<AsyncResult<Boolean>> resultHandler) {

		JsonObject query = new JsonObject()//
				.put("account", account)//
				.put("name", name);

		Future<Boolean> future = Future.future();

		this.mongoClient.removeDocument(COLLECTION_NAME, query, ar -> {
			if (ar.succeeded()) {
				future.complete(ar.result().getRemovedCount() > 0);
			} else {
				future.fail(ar.cause());
			}
		});

		future.setHandler(resultHandler);
	}

}
