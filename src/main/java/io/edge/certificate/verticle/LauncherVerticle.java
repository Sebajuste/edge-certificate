package io.edge.certificate.verticle;

import java.util.ArrayList;
import java.util.List;

import io.vertx.config.ConfigRetriever;
import io.vertx.core.AbstractVerticle;
import io.vertx.core.CompositeFuture;
import io.vertx.core.DeploymentOptions;
import io.vertx.core.Future;
import io.vertx.core.json.JsonObject;

public class LauncherVerticle extends AbstractVerticle {

	@Override
	public void start(Future<Void> startFuture) {

		ConfigRetriever.create(vertx).getConfig(ar -> {

			if (ar.succeeded()) {
				JsonObject config = ar.result();

				DeploymentOptions options = new DeploymentOptions();
				options.setConfig(config);

				@SuppressWarnings("rawtypes")
				List<Future> futureList = new ArrayList<>();

				Future<String> certDeployFuture = Future.future();
				this.vertx.deployVerticle(CertificateVerticle.class.getName(), options, certDeployFuture);
				futureList.add(certDeployFuture);

				CompositeFuture.all(futureList).setHandler(deployResult -> {

					if (deployResult.succeeded()) {
						startFuture.complete();
					} else {
						startFuture.fail(deployResult.cause());
					}

				});

			} else {
				startFuture.fail(ar.cause());
			}

		});

	}

}
