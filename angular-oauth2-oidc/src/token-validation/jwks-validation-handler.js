"use strict";
var __extends = (this && this.__extends) || (function () {
    var extendStatics = Object.setPrototypeOf ||
        ({ __proto__: [] } instanceof Array && function (d, b) { d.__proto__ = b; }) ||
        function (d, b) { for (var p in b) if (b.hasOwnProperty(p)) d[p] = b[p]; };
    return function (d, b) {
        extendStatics(d, b);
        function __() { this.constructor = d; }
        d.prototype = b === null ? Object.create(b) : (__.prototype = b.prototype, new __());
    };
})();
exports.__esModule = true;
var validation_handler_1 = require("./validation-handler");
var rs = require('jsrsasign');
var JwksValidationHandler = (function (_super) {
    __extends(JwksValidationHandler, _super);
    function JwksValidationHandler() {
        var _this = _super !== null && _super.apply(this, arguments) || this;
        _this.allowedAlgorithms = ['RS256'];
        _this.gracePeriodInSec = 600;
        return _this;
    }
    JwksValidationHandler.prototype.validateSignature = function (params) {
        var _this = this;
        if (!params.accessToken)
            throw new Error('Parameter accessToken expected!');
        if (!params.idToken)
            throw new Error('Parameter idToken expected!');
        if (!params.idTokenHeader)
            throw new Error('Parameter idTokenHandler expected.');
        if (!params.jwks)
            throw new Error('Parameter jwks expected!');
        var kid = params.idTokenHeader['kid'];
        var keys = params.jwks['keys'];
        var key = keys.find(function (k) { return k['kid'] == kid && k['use'] == 'sig'; });
        if (!key) {
            var error = 'expected key not found in property jwks. '
                + 'This property is most likely loaded with the '
                + 'discovery document. '
                + 'Expected key id (kid): ' + kid;
            console.error(error);
            return Promise.reject(error);
        }
        var keyObj = rs.KEYUTIL.getKey(key);
        return new Promise(function (resolve, reject) {
            return setTimeout(function () {
                var isValid = rs.KJUR.jws.JWS.verifyJWT(params.idToken, keyObj, { alg: _this.allowedAlgorithms, gracePeriod: _this.gracePeriodInSec });
                console.debug('isValid', isValid);
                if (isValid) {
                    //return Promise.resolve();
                    resolve();
                }
                else {
                    //return Promise.reject('Signature not valid');
                    reject('Signature not valid');
                }
            }, 1000);
        });
    };
    JwksValidationHandler.prototype.calcHash = function (valueToHash, algorithm) {
        var hashAlg = new rs.KJUR.crypto.MessageDigest({ alg: algorithm });
        var result = hashAlg.digestString(valueToHash);
        var byteArrayAsString = this.toByteArrayAsString(result);
        return byteArrayAsString;
    };
    JwksValidationHandler.prototype.toByteArrayAsString = function (hexString) {
        var result = "";
        for (var i = 0; i < hexString.length; i += 2) {
            var hexDigit = hexString.charAt(i) + hexString.charAt(i + 1);
            var num = parseInt(hexDigit, 16);
            result += String.fromCharCode(num);
        }
        return result;
    };
    return JwksValidationHandler;
}(validation_handler_1.AbstractValidationHandler));
exports.JwksValidationHandler = JwksValidationHandler;
