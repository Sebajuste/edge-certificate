package io.edge.certificate.verticle;

import io.edge.certificate.dao.CertificateDao;
import io.edge.certificate.dao.mongo.CertificateDaoMongo;
import io.edge.certificate.service.CertificateService;
import io.edge.certificate.service.CertificateServiceAPI;
import io.edge.certificate.service.impl.CertificateServiceAPIImpl;
import io.edge.certificate.service.impl.CertificateServiceImpl;
import io.edge.utils.webapiservice.WebApiService;
import io.vertx.core.AbstractVerticle;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.mongo.MongoClient;
import io.vertx.serviceproxy.ServiceBinder;

public class CertificateVerticle extends AbstractVerticle {

	@Override
	public void start() {

		JsonObject mongoConfig = new JsonObject();

		mongoConfig.put("host", config().getString("mongodb.host", "localhost"));
		mongoConfig.put("port", config().getInteger("mongodb.port", 27017));

		mongoConfig.put("db_name", config().getString("mongodb.dbname", "edge_certificates"));

		if (config().containsKey("mongodb.user")) {
			mongoConfig.put("username", config().getString("mongodb.user"));
		}

		if (config().containsKey("mongodb.password")) {
			mongoConfig.put("password", config().getString("mongodb.password"));
		}

		MongoClient mongoClient = MongoClient.createShared(vertx, mongoConfig);

		CertificateDao certificateDao = new CertificateDaoMongo(vertx, mongoClient);

		/*
		 * Bus Service
		 */

		ServiceBinder serviceBinder = new ServiceBinder(vertx);

		CertificateService certificateService = new CertificateServiceImpl(certificateDao);

		serviceBinder.setAddress(CertificateService.ADDRESS).register(CertificateService.class, certificateService);

		/*
		 * API Service
		 */
		
		serviceBinder.setAddress(CertificateServiceAPI.ADDRESS).register(CertificateServiceAPI.class, new CertificateServiceAPIImpl(certificateService));
		
		JsonObject config = new JsonObject()//
				.put("name", "IoT-Shadow")//
				.put("endpoint", "io.edge.certificates.webapi-service.yaml")//
				.put("file", "src/main/resources/certificate-api.yaml")//
				.put("subpath", "/certificates-service");

		WebApiService.create(vertx).bind(config);
		
	}

}
