"use strict";
exports.__esModule = true;
var NullValidationHandler = (function () {
    function NullValidationHandler() {
    }
    NullValidationHandler.prototype.validateSignature = function (validationParams) {
        return Promise.resolve(null);
    };
    NullValidationHandler.prototype.validateAtHash = function (validationParams) {
        return true;
    };
    return NullValidationHandler;
}());
exports.NullValidationHandler = NullValidationHandler;
