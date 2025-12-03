module se.uu.ub.cora.idplogin {
	requires se.uu.ub.cora.logger;
	requires se.uu.ub.cora.gatekeepertokenprovider;
	requires se.uu.ub.cora.json;
	requires jakarta.servlet;
	requires owasp.encoder;

	exports se.uu.ub.cora.idplogin.json;
}