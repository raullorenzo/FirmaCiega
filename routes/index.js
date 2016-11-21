var express = require('express');
var bignum = require('bignum');
var rsa = require('../rsa/rsa-bignum');
var path = require('path');
var router = express.Router();

var keys = rsa.generateKeys(1024, function (keys) {
    console.log("Keys are ready!");
    console.log(keys);
});

/* GET home page. */
router.get('/', function (req, res, next) {
    res.sendFile(path.join(__dirname, '../public', 'ttp.html'));
});

router.post('/', function (req, res, next) {
    console.log(req.body);
    var blind = bignum(req.body.blind);
    var d = keys.privateKey.d.toString();
    var n = keys.publicKey.n.toString();
    console.log("LA clave privada del servidor d: ", d);
    console.log("LA n: ", n);
    console.log(blind);
    //AQUI NO ME VA me salta que la bc.powm no es una funcion --que raro-- en pallier me pasa lo mismo//
    var teta = keys.privateKey.encrypt(blind);
    console.log(teta);
    //SI FUNCIONA LO ANTERIOR EL SERVIDOR TE DA UNA FIRMA VALIDA"
    var sign = {
        teta: teta.toString()
    };
    res.send(JSON.stringify(sign));
});

router.get('/publicKey', function (req, res, next) {
    var publickey = {
        bits: keys.publicKey.bits,
        n: keys.publicKey.n.toString(),
        e: keys.publicKey.e.toString()
    };
    console.log(publickey);
    res.send(JSON.stringify(publickey));

});

module.exports = router;