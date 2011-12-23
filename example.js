var sasl = require('./sasl');
var sys = require('sys');

sasl_conn = sasl.createServerSession(function(prop) {
        if(prop == sasl.GSASL_REALM)
            return "localhost";
});
sasl_conn.start("DIGEST-MD5");
sys.debug( sys.inspect( sasl_conn ) );
sys.debug( sasl_conn.property("realm") );
sasl_conn.setProperty("realm", "localhost");
sys.debug( sasl_conn.property("realm") );
sys.debug( sys.inspect(sasl));
sys.debug( sasl_conn.step("").status );
//sys.debug( sys.inspect( sasl ) );

