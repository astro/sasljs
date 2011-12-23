var saslc = require('./build/Release/lib/binding_sasl');
var sys = require('sys');

Object.keys(saslc).forEach(function(elt) {
    if( typeof(saslc[elt]) == "number" )
        exports[elt] = saslc[elt];
});

exports.createServerSession = function(callback) {
    var serv = new saslc.ServerSession( callback );
    serv.mechanisms = serv._mechanisms().split(' ');
    // POP empty element
    serv.mechanisms.pop();
    return serv;
};

exports.createClientSession = function(callback) {
    var client = new saslc.ClientSession( callback );
    client.mechanisms = client._mechanisms().split(' ');
    return client;
};
