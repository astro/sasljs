var vows = require('vows'),
assert = require('assert'),
sasl = require('../sasl');

vows.describe("ClientSession").addBatch({
    'ANONYMOUS': {
	"has a list of mechanisms": function() {
	    var c = sasl.createClientSession(function(prop) {
		return 0;
	    });
	    assert.ok(c.mechanisms.length > 0);
	    assert.equal(typeof c.mechanisms[0], 'string');
	},
	"calls back for unknown properties": function() {
	    var callbackProp;
	    var c = sasl.createClientSession(function(prop) {
		c.setProperty('anonymous_token', "foobar");
		callbackProp = prop;
		return 0;
	    });
	    assert.equal(c.start("ANONYMOUS"), 0);
	    assert.equal(callbackProp, undefined);
	    var stepResult = c.step("");
	    assert.equal(callbackProp, 'anonymous_token');
	    assert.equal(stepResult.status, 0);
	    assert.equal(stepResult.data.length, "foobar".length * 4 / 3);
	},
	"does not call back for known properties": function() {
	    var callbackProp;
	    var c = sasl.createClientSession(function(prop) {
		console.log("prop", prop);
		callbackProp = prop;
		return 0;
	    });
	    assert.equal(c.start("ANONYMOUS"), 0);
	    assert.equal(callbackProp, undefined);
	    c.setProperty('anonymous_token', "foobar");
	    var stepResult = c.step("");
	    assert.equal(callbackProp, undefined);
	    assert.equal(stepResult.status, 0);
	    assert.equal(stepResult.data.length, "foobar".length * 4 / 3);
	},

    }
}).export(module);
