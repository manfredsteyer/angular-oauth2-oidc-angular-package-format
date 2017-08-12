import { ValidationHandler } from "./validation-handler";

let rs = require('jsrsasign');

export const JwksValidationHandler: ValidationHandler = function(params) {
    
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

    //let hash = new rs.KJUR.crypto.MessageDigest({alg: "sha256"});
    //console.debug('hash', hash);
    
    let keyObj = rs.KEYUTIL.getKey(key);
    let isValid = rs.KJUR.jws.JWS.verifyJWT(params.idToken, keyObj, { alg: ['RS256'] });
    
    console.debug('isValid', isValid);

    if (isValid) {
        return Promise.resolve();
    }
    
    return Promise.reject('Signature not valid');

}