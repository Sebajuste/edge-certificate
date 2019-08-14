package io.edge.certificate.dao.mongo;

import java.util.List;

import io.edge.certificate.dao.CertificateDao;
import io.vertx.core.AsyncResult;
import io.vertx.core.Handler;
import io.vertx.core.Promise;
import io.vertx.core.Vertx;
import io.vertx.core.json.JsonObject;
import io.vertx.core.logging.Logger;
import io.vertx.core.logging.LoggerFactory;
import io.vertx.ext.mongo.MongoClient;
import io.vertx.ext.mongo.UpdateOptions;

public class CertificateDaoMongo implements CertificateDao {

	private static final Logger LOGGER = LoggerFactory.getLogger(CertificateDaoMongo.class);

	private static final String COLLECTION_NAME = "certificates";

	private final MongoClient mongoClient;

	public CertificateDaoMongo(final Vertx vertx, final MongoClient mongoClient) {
		this.mongoClient = mongoClient;
	}

	@Override
	public void saveCertificate(String account, String name, JsonObject keys, String certificate, Handler<AsyncResult<Boolean>> resultHandler) {

		JsonObject query = new JsonObject()//
				.put("account", account)//
				.put("name", name);

		JsonObject update = new JsonObject()//
				.put("$set", new JsonObject().put("keys", keys).put("certificate", certificate));

		UpdateOptions options = new UpdateOptions();
		options.setUpsert(true);

		Promise<Boolean> promise = Promise.promise();
		
		promise.future().setHandler(resultHandler);

		this.mongoClient.updateCollectionWithOptions(CertificateDaoMongo.COLLECTION_NAME, query, update, options, ar -> {

			if (ar.succeeded()) {
				promise.complete(ar.result().getDocModified() > 0);
			} else {
				LOGGER.error("Error persist certificate : " + ar.cause().getMessage(), ar.cause());
				promise.fail(ar.cause());
			}

		});

		

	}

	@Override
	public void getAllCertificates(String account, Handler<AsyncResult<List<JsonObject>>> resultHandler) {

		JsonObject query = new JsonObject().put("account", account);

		this.mongoClient.find(COLLECTION_NAME, query, resultHandler);

	}

	@Override
	public void findCertificate(String account, String name, boolean loadKeys, Handler<AsyncResult<JsonObject>> resultHandler) {

		JsonObject query = new JsonObject()//
				.put("account", account)//
				.put("name", name);

		JsonObject fields = new JsonObject()
				.put("certificate", 1);
		
		if( loadKeys ) {
			fields.put("keys", 1);
		}

		Promise<JsonObject> promise = Promise.promise();
		
		promise.future().setHandler(resultHandler);

		this.mongoClient.findOne(COLLECTION_NAME, query, fields, ar -> {

			if (ar.succeeded()) {

				JsonObject result = ar.result();

				if (result != null) {

					JsonObject certificate = new JsonObject()//
							.put("certificate", result.getString("certificate"));

					if (loadKeys) {
						certificate.put("keys", result.getJsonObject("keys"));
					}

					promise.complete(certificate);
				} else {
					promise.complete();
				}
			} else {
				LOGGER.error(ar.cause());
				promise.fail(ar.cause());
			}

		});

	}

	@Override
	public void deleteCertificate(String account, String name, Handler<AsyncResult<Boolean>> resultHandler) {

		JsonObject query = new JsonObject()//
				.put("account", account)//
				.put("name", name);

		Promise<Boolean> promise = Promise.promise();
		
		promise.future().setHandler(resultHandler);

		this.mongoClient.removeDocument(COLLECTION_NAME, query, ar -> {
			if (ar.succeeded()) {
				promise.complete(ar.result().getRemovedCount() > 0);
			} else {
				promise.fail(ar.cause());
			}
		});

	}

}
