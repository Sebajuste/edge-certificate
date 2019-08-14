package io.edge.certificate.verticle;

import java.util.ArrayList;
import java.util.List;

import io.vertx.config.ConfigRetriever;
import io.vertx.core.AbstractVerticle;
import io.vertx.core.CompositeFuture;
import io.vertx.core.DeploymentOptions;
import io.vertx.core.Future;
import io.vertx.core.Promise;
import io.vertx.core.json.JsonObject;

public class LauncherVerticle extends AbstractVerticle {

	@Override
	public void start(Promise<Void> startPromise) {

		ConfigRetriever.create(vertx).getConfig(ar -> {

			if (ar.succeeded()) {
				JsonObject config = ar.result();

				DeploymentOptions options = new DeploymentOptions();
				options.setConfig(config);

				@SuppressWarnings("rawtypes")
				List<Future> futureList = new ArrayList<>();

				Promise<String> certDeployPromise = Promise.promise();
				this.vertx.deployVerticle(CertificateVerticle.class.getName(), options, certDeployPromise);
				futureList.add(certDeployPromise.future());

				CompositeFuture.all(futureList).setHandler(deployResult -> {

					if (deployResult.succeeded()) {
						startPromise.complete();
					} else {
						startPromise.fail(deployResult.cause());
					}

				});

			} else {
				startPromise.fail(ar.cause());
			}

		});

	}

}
