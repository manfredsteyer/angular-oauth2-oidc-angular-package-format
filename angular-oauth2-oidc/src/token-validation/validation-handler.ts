export interface ValidationParams {
    idToken: string;
    accessToken: string;
    idTokenHeader: object;
    idTokenClaims: object;
    jwks: object;
}

export interface ValidationHandler {
    validateSignature(validationParams: ValidationParams): Promise<any>;    
    validateAtHash(validationParams: ValidationParams): boolean;    
} 

export abstract class AbstractValidationHandler implements ValidationHandler {
    abstract validateSignature(validationParams: ValidationParams): Promise<any>;    
    
    validateAtHash(params: ValidationParams): boolean {
        
        let hashAlg = this.inferHashAlgorithm(params.idTokenHeader);

        var tokenHash = this.calcHash(params.accessToken, hashAlg); //sha256(accessToken, { asString: true });
        
        var leftMostHalf = tokenHash.substr(0, tokenHash.length / 2 );
        
        var tokenHashBase64 = btoa(leftMostHalf);

        var atHash = tokenHashBase64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
        var claimsAtHash = params.idTokenClaims['at_hash'].replace(/=/g, "");
        var atHash = tokenHashBase64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");

        if (atHash != claimsAtHash) {
            console.error("exptected at_hash: " + atHash);    
            console.error("actual at_hash: " + claimsAtHash);
        }
        
        return (atHash == claimsAtHash);
    }

    inferHashAlgorithm(jwtHeader: object): string {
        let alg: string = jwtHeader['alg'];

        if (!alg.match(/^.S[0-9]{3}$/)) {
            throw new Error('Algorithm not supported: ' + alg);
        }

        return 'sha' + alg.substr(2);
    }

    abstract calcHash(valueToHash: string, algorithm: string): string;
    


}