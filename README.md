Edge Certificate
------

Create and manage X509 Certificate.

Algorithm supported:

- SHA128withRSA 1024 bits
- SHA256withRSA 1024 bits
- SHA256withECDSA 256 bits
- SHA1withECDSA 256 bits

### Vert.x Service

The service is only available on Hezelcast cluster through Vert.x event bus service.

Create a [proxy](http://vertx.io/docs/vertx-service-proxy/java/#_proxy_creation) with io.edge.certificate.service.CertificateService to use it.

### Web API

Expose certificate management through [Edge API](https://github.com/Sebajuste/edge-api)

See [OpenAPI](src/main/resources/certificate-api.yaml)


### Certificate persistence

All certificate create are stored in MongoDB.

Configuration:

- **mongodb.host** Host of the database *(Default localhost)*
- **mongodb.port** Port of the database *(Default 27017)*
- **mongodb.dbname** Name of the database *(Default edge_certificates)*
- **mongodb.user** Username of the database *(Optional)*
- **mongodb.password** Password of the database *(Optional)*
