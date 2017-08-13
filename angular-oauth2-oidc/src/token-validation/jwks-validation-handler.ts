import { ValidationHandler, AbstractValidationHandler, ValidationParams } from "./validation-handler";

declare var require: any;
let rs = require('jsrsasign');

export class JwksValidationHandler extends AbstractValidationHandler {
    

    allowedAlgorithms: string[] = ['RS256'];
    gracePeriodInSec: 300;

    validateSignature(params: ValidationParams): Promise<any> {
        if (!params.accessToken) throw new Error('Parameter accessToken expected!');
        if (!params.idToken) throw new Error('Parameter idToken expected!');
        if (!params.idTokenHeader) throw new Error('Parameter idTokenHandler expected.');
        if (!params.jwks) throw new Error('Parameter jwks expected!');
    
        let kid: string = params.idTokenHeader['kid'];
        let keys: object[] = params.jwks['keys'];
        let key: object = keys.find(k => k['kid'] == kid && k['use'] == 'sig');
    
        if (!key) {
            let error = 'expected key not found in property jwks. '
                            + 'This property is most likely loaded with the '
                            + 'discovery document. '
                            + 'Expected key id (kid): ' + kid;
    
            console.error(error);
            return Promise.reject(error);
        }
    
        let keyObj = rs.KEYUTIL.getKey(key);
        let isValid = rs.KJUR.jws.JWS.verifyJWT(params.idToken, keyObj, { alg: this.allowedAlgorithms, gracePeriod: this.gracePeriodInSec });
        
        console.debug('isValid', isValid);
    
        if (isValid) {
            return Promise.resolve();
        }
        
        return Promise.reject('Signature not valid');
    
    }

    calcHash(valueToHash: string, algorithm: string): string {
        let hashAlg = new rs.KJUR.crypto.MessageDigest({alg: algorithm});
        let result = hashAlg.digestString(valueToHash);
        let byteArrayAsString = this.toByteArrayAsString(result);
        return byteArrayAsString;
    }

    toByteArrayAsString(hexString: string) {
        let result: string = "";
        for(let i=0; i<hexString.length; i+=2) {
            let hexDigit = hexString.charAt(i) + hexString.charAt(i+1);
            let num = parseInt(hexDigit, 16);
            result += String.fromCharCode(num);
        }
        return result;
    }

}

