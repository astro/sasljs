var vows = require('vows'),
assert = require('assert'),
sasl = require('../sasl');

vows.describe("Client-Server Dialogue").addBatch({
    'ANONYMOUS': {
	"should authenticate": function() {
	    var s = sasl.createServerSession(function(prop) {
		return 0;
	    });
	    var c = sasl.createClientSession(function(prop) {
		return 0;
	    });
	    assert.equal(c.start("ANONYMOUS"), 0);
	    c.setProperty("anonymous_token", "foobar");
	    assert.equal(s.start("ANONYMOUS"), 0);
	    var input = "";
	    do {
		var stepResult = c.step(input);
		assert.equal(stepResult.status, 0);
		assert.ok(stepResult.data.length > 0);
		input = stepResult.data || "";
		stepResult = s.step(input);
		assert.equal(stepResult.status, 0);
		input = stepResult.data || "";
	    } while(input !== "");
	}
    },
    'PLAIN': {
	"should authenticate": function() {
	    var s = sasl.createServerSession(function(prop) {
		console.log("s prop", prop);
		return 0;
	    });
	    var c = sasl.createClientSession(function(prop) {
		console.log("c prop", prop);
		return 0;
	    });
	    console.log("c start", c.start("PLAIN"));
	    c.setProperty("authid", "peter");
	    c.setProperty("password", "secret");
	    console.log("s start", s.start("PLAIN"));
	    var input = "";
	    do {
		var stepResult = c.step(input);
		assert.equal(stepResult.status, 0);
		assert.ok(stepResult.data.length > 0);
		input = stepResult.data || "";
		stepResult = s.step(input);
		assert.equal(stepResult.status, 0);
		input = stepResult.data || "";
	    } while(input !== "");
	}
    },
    'DIGEST-MD5': {
	"should authenticate": function() {
	    var s = sasl.createServerSession(function(prop) {
		console.log("s prop", prop);
		if (prop === 'password')
		    s.setProperty("password", "secret");
		return 0;
	    });
	    var c = sasl.createClientSession(function(prop) {
		console.log("c prop", prop);
		return 0;
	    });
	    console.log("c start", c.start("DIGEST-MD5"));
	    c.setProperty("authid", "peter");
	    c.setProperty("password", "secret");
	    c.setProperty("service", "xmpp");
	    c.setProperty("hostname", "example.org");
	    console.log("s start", s.start("DIGEST-MD5"));
	    var input = "";
	    do {
		var stepResult = s.step(input);
		console.log("s step", stepResult);
		input = stepResult.data || "";
		stepResult = c.step(input);
		console.log("c step", stepResult);
		input = stepResult.data || "";
	    } while(stepResult.status === 1);
	    assert.equal(stepResult.status, 0);
	}
    }
}).export(module);
