var saslc = require('./build/Release/lib/binding_sasl');
var sys = require('sys');

Object.keys(saslc).forEach(function(elt) {
    if( typeof(saslc[elt]) == "number" )
        exports[elt] = saslc[elt];
});

exports.createServerSession = function(realm, callback) {
    var serv = new saslc.ServerSession( realm, callback );
    serv.mechanisms = serv._mechanisms().split(' ');
    // POP empty element
    serv.mechanisms.pop();
    return serv;
};

exports.createClientSession = function(realm, callback) {
    var client = new saslc.ClientSession( realm, callback );
    client.mechanisms = client._mechanisms().split(' ');
    return client;
};
