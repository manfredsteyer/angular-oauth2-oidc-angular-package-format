import {Base64} from 'js-base64';
import {fromByteArray} from 'base64-js';
import * as sha256Module from 'sha256';
import { Http, URLSearchParams, Headers } from '@angular/http';
import { Injectable } from '@angular/core';
import { Observable } from 'rxjs/Observable';
import { Subject } from 'rxjs/Subject';
import { ValidationHandler } from "./token-validation/validation-handler";
import { NullValidationHandler } from "./token-validation/null-validation-handler";

var sha256: any = require('sha256');

export class LoginOptions {
    onTokenReceived?: (receivedTokens: ReceivedTokens) => void;
    validationHandler?: ValidationHandler;
    onLoginError?: (params: object) => void;
    customHashFragment?: string;
}

/**
 * Represents the received tokens, the received state
 * and the parsed claims from the id-token.
 */
export class ReceivedTokens {
    idToken: string;
    accessToken: string;
    idClaims?: object;
    state?: string
}

export abstract class OAuthEvent {
    constructor(
        readonly type: string) {
    }
}

export class OAuthSuccessEvent extends OAuthEvent {
}

export class OAuthErrorEvent extends OAuthEvent {

    constructor(
        type: string,
        readonly reason: object,
        readonly params: object = null
    ) {
        super(type);
    }

}
    

@Injectable()
export class OAuthService {

    public clientId = "";
    public redirectUri = "";
    public postLogoutRedirectUri = "";
    public loginUrl = "";
    public scope = "openid profile";
    public resource = "";
    public rngUrl = "";
    public oidc = true;
    public options: any;
    public state = "";
    public issuer = "";
    public validationHandler: any;
    public logoutUrl = "";
    public clearHashAfterLogin: boolean = true;
    public tokenEndpoint: string;
    public userinfoEndpoint: string;
    public responseType: string = "token";
    public showDebugInformation: boolean = false;
    public silentRefreshRedirectUri: string = '';
    public silentRefreshMessagePrefix: string = '';
    public siletRefreshTimeout: number = 1000 * 20; 
    public dummyClientSecret: string;
    public tokenValidationHandler: ValidationHandler = NullValidationHandler;
    public jwks: object;

    public discoveryDocumentLoaded: boolean = false;
  
    /**
     * @deprecated use property events instead
     */
    public discoveryDocumentLoaded$: Observable<object>;
    private discoveryDocumentLoadedSubject: Subject<object> = new Subject<object>();

    public events: Observable<OAuthEvent>;
    private eventsSubject: Subject<OAuthEvent> = new Subject<OAuthEvent>();

    public silentRefreshIFrameName: string = 'angular-oauth-oidc-silent-refresh-iframe';

    private silentRefreshPostMessageEventListener: EventListener;

    private grantTypesSupported: Array<string> = [];

    private _storage: Storage = localStorage;

    constructor(private http: Http) {
       this.discoveryDocumentLoaded$ = this.discoveryDocumentLoadedSubject.asObservable();
       this.events = this.eventsSubject.asObservable();
    }

    private debug(...args): void {
        if (this.showDebugInformation) {
            console.debug.apply(console, args);
        }
    }

    public setStorage(storage: Storage): void {
        this._storage = storage;
    }

    loadDiscoveryDocument(fullUrl: string = null): Promise<object> {


        return new Promise((resolve, reject) => {

            if (!fullUrl) {
                fullUrl = this.issuer + '/.well-known/openid-configuration';
            }

            this.http.get(fullUrl).map(r => r.json()).subscribe(
                (doc) => {

                    this.loginUrl = doc.authorization_endpoint;
                    this.logoutUrl = doc.end_session_endpoint;
                    this.grantTypesSupported = doc.grant_types_supported;
                    this.issuer = doc.issuer;
                    this.tokenEndpoint = doc.token_endpoint;
                    this.userinfoEndpoint = doc.userinfo_endpoint;

                    this.discoveryDocumentLoaded = true;
                    this.discoveryDocumentLoadedSubject.next(doc);

                    if (doc.jwks_uri) {
                        this.http.get(doc.jwks_uri).map(r => r.json()).subscribe(
                            jwks => {
                                this.jwks = jwks;
                                this.eventsSubject.next(new OAuthSuccessEvent('discovery_document_loaded'));
                                resolve(doc);
                            },
                            err => {
                                console.error('error loading jwks', err);
                                this.eventsSubject.next(new OAuthErrorEvent('jwks_load_error', err));
                                reject(err);
                            }
                        )
                    }
                    else {
                        this.eventsSubject.next(new OAuthSuccessEvent('discovery_document_loaded'));
                        resolve(doc);
                    }
                },
                (err) => {
                    console.error('error loading dicovery document', err);
                    this.eventsSubject.next(new OAuthErrorEvent('discovery_document_load_error', err));
                    reject(err);
                }
            );
        });
    }

    fetchTokenUsingPasswordFlowAndLoadUserProfile(userName: string, password: string, headers: Headers = new Headers()): Promise<object> {
        return this
                .fetchTokenUsingPasswordFlow(userName, password, headers)
                .then(() => this.loadUserProfile());
    }

    loadUserProfile(): Promise<object> {
        if (!this.hasValidAccessToken()) throw Error("Can not load User Profile without access_token");

        return new Promise((resolve, reject) => {

            let headers = new Headers();
            headers.set('Authorization', 'Bearer ' + this.getAccessToken());

            this.http.get(this.userinfoEndpoint, { headers }).map(r => r.json()).subscribe(
                (doc) => {
                    this.debug('userinfo received', doc);
                    this._storage.setItem('id_token_claims_obj', JSON.stringify(doc));
                    this.eventsSubject.next(new OAuthSuccessEvent('user_profile_loaded'));
                    resolve(doc);
                },
                (err) => {
                    console.error('error loading user info', err);
                    this.eventsSubject.next(new OAuthErrorEvent('user_profile_load_error', err));
                    reject(err);
                }
            );
        });


    }

    fetchTokenUsingPasswordFlow(userName: string, password: string, headers: Headers = new Headers()): Promise<object> {

        return new Promise((resolve, reject) => { 
            let search = new URLSearchParams();
            search.set('grant_type', 'password');
            search.set('client_id', this.clientId);
            search.set('scope', this.scope);
            search.set('username', userName);
            search.set('password', password);
            
            if (this.dummyClientSecret) {
                search.set('client_secret', this.dummyClientSecret);
            }

            headers.set('Content-Type', 'application/x-www-form-urlencoded');

            let params = search.toString();

            this.http.post(this.tokenEndpoint, params, { headers }).map(r => r.json()).subscribe(
                (tokenResponse) => {
                    this.debug('tokenResponse', tokenResponse);
                    this.storeAccessTokenResponse(tokenResponse.access_token, tokenResponse.refresh_token, tokenResponse.expires_in);

                    this.eventsSubject.next(new OAuthSuccessEvent('token_received'));
                    resolve(tokenResponse);
                },
                (err) => {
                    console.error('Error performing password flow', err);
                    this.eventsSubject.next(new OAuthErrorEvent('token_error', err));
                    reject(err);
                }
            );
        });

    }

    /**
     * Refreshes the token using a refresh_token.
     * This does not work for implicit flow, b/c
     * there is no refresh_token in this flow.
     * A solution for this is provided by the
     * method silentRefresh.
     */
    refreshToken(): Promise<object> {

        return new Promise((resolve, reject) => { 
            let search = new URLSearchParams();
            search.set('grant_type', 'refresh_token');
            search.set('client_id', this.clientId);
            search.set('scope', this.scope);
            search.set('refresh_token', this._storage.getItem('refresh_token'));
            
            if (this.dummyClientSecret) {
                search.set('client_secret', this.dummyClientSecret);
            }

            let headers = new Headers();
            headers.set('Content-Type', 'application/x-www-form-urlencoded');

            let params = search.toString();

            this.http.post(this.tokenEndpoint, params, { headers }).map(r => r.json()).subscribe(
                (tokenResponse) => {
                    this.debug('refresh tokenResponse', tokenResponse);
                    this.storeAccessTokenResponse(tokenResponse.access_token, tokenResponse.refresh_token, tokenResponse.expires_in);
                    
                    this.eventsSubject.next(new OAuthSuccessEvent('token_refreshed'));
                    resolve(tokenResponse);
                },
                (err) => {
                    console.error('Error performing password flow', err);
                    this.eventsSubject.next(new OAuthErrorEvent('token_refresh_error', err));
                    reject(err);
                }
            );
        });
    }

    private removeSilentRefreshEventListener(): void {
        if (this.silentRefreshPostMessageEventListener) {
            window.removeEventListener('message', this.silentRefreshPostMessageEventListener);
            this.silentRefreshPostMessageEventListener = null;
        }
    }

    private setupSilentRefreshEventListener(): void {
        this.removeSilentRefreshEventListener();
        
        this.silentRefreshPostMessageEventListener = (e: MessageEvent) => {

            let expectedPrefix = '#';

            if (this.silentRefreshMessagePrefix) {
                expectedPrefix += this.silentRefreshMessagePrefix;
            }

            if (!e || !e.data || typeof e.data != 'string' ) return;
            
            let prefixedMessage: string = e.data;

            if (!prefixedMessage.startsWith(expectedPrefix)) return;

            let message = prefixedMessage.substr(expectedPrefix.length);

            this.tryLogin({
                customHashFragment: message,
                onLoginError: (err) => {
                    this.eventsSubject.next(new OAuthErrorEvent('silent_refresh_error', err));
                },
                onTokenReceived: () => {
                    this.eventsSubject.next(new OAuthSuccessEvent('silent_refreshed'));
                }
            });
        }

        window.addEventListener('message', this.silentRefreshPostMessageEventListener);
    }

    
    /**
     * Performs a silent refresh for implicit flow.
     */
    silentRefresh(): Promise<OAuthEvent> {
        
        if (!document) {
            throw new Error('silent refresh is not supported on this platform');
        } 

        let existingIframe = document.getElementById(this.silentRefreshIFrameName);
        if (existingIframe) {
            document.body.removeChild(existingIframe);
        }

        let iframe = document.createElement('iframe');
        iframe.id = this.silentRefreshIFrameName;

        this.setupSilentRefreshEventListener();

        let redirectUri = this.silentRefreshRedirectUri || this.redirectUri;
        this.createLoginUrl(null, null, redirectUri).then(url => {
            iframe.setAttribute('src', url);
            document.body.appendChild(iframe);
        });

        let errors = this.events.filter(e => e instanceof OAuthErrorEvent).first();
        let success = this.events.filter(e => e.type == 'silent_refreshed').first();
        let timeout = Observable.of(new OAuthErrorEvent('silent_refresh_timeout', null))
                                .delay(this.siletRefreshTimeout);

        let result = Observable.race([errors, success, timeout]).publish();
        result.connect();

        result
            .filter( (e: OAuthEvent) => e.type == 'silent_refresh_timeout')
            .subscribe(e => this.eventsSubject.next(e));

        return result.map(e => {
            if (e instanceof OAuthErrorEvent) {
                throw e;
            }
            return e;
        }).toPromise();
    }
    
    createLoginUrl(
        state: string = '', 
        loginHint: string = '',
        customRedirectUri: string = ''
    ) {
        var that = this;

        let redirectUri: string;

        if (customRedirectUri) {
            redirectUri = customRedirectUri;
        }
        else {
            redirectUri = this.redirectUri;
        }

        return this.createAndSaveNonce().then(function (nonce: any) {

            if (state) {
                state = nonce + ";" + state;
            }
            else {
                state = nonce;   
            }

            if (that.oidc) {
                that.responseType = "id_token token";
            }

            var url = that.loginUrl 
                        + "?response_type="
                        + encodeURIComponent(that.responseType)
                        + "&client_id="
                        + encodeURIComponent(that.clientId)
                        + "&state=" 
                        + encodeURIComponent(state)
                        + "&redirect_uri=" 
                        + encodeURIComponent(redirectUri) 
                        + "&scope=" 
                        + encodeURIComponent(that.scope)
                        + "&login_hint="
                        + encodeURIComponent(loginHint);

            if (that.resource) {
                url += "&resource=" + encodeURIComponent(that.resource);
            }
            
            if (that.oidc) {
                url += "&nonce=" + encodeURIComponent(nonce);
            }
            
            return url;
        });
    };

    initImplicitFlow(additionalState = "", loginHint=""): void {
        this.createLoginUrl(additionalState, loginHint).then(function (url) {
            location.href = url;
        })
        .catch(error => {
            console.error("Error in initImplicitFlow");
            console.error(error);
        });
    };
    
    private callOnTokenReceivedIfExists(options: LoginOptions): void {
        var that = this;
        if (options.onTokenReceived) {
            var tokenParams = { 
                idClaims: that.getIdentityClaims(),
                idToken: that.getIdToken(),
                accessToken: that.getAccessToken(),
                state: that.state
            };
            options.onTokenReceived(tokenParams);
        }
    }

    private storeAccessTokenResponse(accessToken: string, refreshToken: string, expiresIn: number): void {
        this._storage.setItem("access_token", accessToken);

        if (expiresIn) {
            var expiresInMilliSeconds = expiresIn * 1000;
            var now = new Date();
            var expiresAt = now.getTime() + expiresInMilliSeconds;
            this._storage.setItem("expires_at", "" + expiresAt);
        }

        if (refreshToken) {
            this._storage.setItem("refresh_token", refreshToken);
        }
    }

    tryLogin(options: LoginOptions = null) {
        
        options = options || { };
            
        let parts: object;

        if (options.customHashFragment) {
            parts = this.parseQueryString(options.customHashFragment);
        }
        else {
            parts = this.getFragment();
        }

        if (parts["error"]) {
            this.debug('error trying to login');
            this.handleLoginError(options, parts);
            
            this.eventsSubject.next(new OAuthErrorEvent('token_error', {}, parts));

            return false;
        }

        var accessToken = parts["access_token"];
        var idToken = parts["id_token"];
        var state = decodeURIComponent(parts["state"]);
        
        var oidcSuccess = false;
        var oauthSuccess = false;

        if (!accessToken || !state) return false;
        if (this.oidc && !idToken) return false;

        var savedNonce = this._storage.getItem("nonce");

        // Our state might be URL encoded
        // Check for this and then decode it if it is
        let decodedState = decodeURIComponent(state);
        if (decodedState != state) {
          state = decodedState;
        }
        
        var stateParts = state.split(';');
        var nonceInState = stateParts[0];
        if (savedNonce === nonceInState) {
            
            this.storeAccessTokenResponse(accessToken, null, parts['expires_in']);

            if (stateParts.length > 1) {
                this.state = stateParts[1];
            }

            oauthSuccess = true;

        }
        
        if (!oauthSuccess) return false;

        let idTokenResult = {};

        if (!this.oidc) return true;

        idTokenResult = this.processIdToken(idToken, accessToken);
        if (!idTokenResult) {
            this.eventsSubject.next(new OAuthErrorEvent('validation_error', {}));
            return false;  
        }        
        
        if (!options.validationHandler) {
            options.validationHandler = this.validationHandler;
        }

        if (options.validationHandler) {
            
            let idTokenHeader = null;
            let idTokenHeaderJson = idTokenResult['id_token_header_obj'];
            if (idTokenHeaderJson) {
                idTokenHeader = JSON.parse(idTokenHeaderJson)
            }

            var validationParams = { 
                accessToken: accessToken, 
                idToken: idToken,
                idTokenHeader: idTokenHeader,
                jwks: this.jwks
            };
            
            options
                .validationHandler(validationParams)
                .then(() => {
                    this._storage.setItem("id_token", idTokenResult['id_token']);
                    this._storage.setItem("id_token_claims_obj", idTokenResult['id_token_claims_obj']);
                    this._storage.setItem("id_token_expires_at", "" + idTokenResult['id_token_expires_at']);

                    this.eventsSubject.next(new OAuthSuccessEvent('token_received'));
                    this.callOnTokenReceivedIfExists(options);
                })
                .catch(reason => {
                    this.eventsSubject.next(new OAuthErrorEvent('validation_error', reason));
                    console.error('Error validating tokens');
                    console.error(reason);
                })
        }
        else {
            this._storage.setItem("id_token", idTokenResult['id_token']);
            this._storage.setItem("id_token_claims_obj", idTokenResult['id_token_claims_obj']);
            this._storage.setItem("id_token_expires_at", "" + idTokenResult['id_token_expires_at']);

            this.eventsSubject.next(new OAuthSuccessEvent('token_received'));
            this.callOnTokenReceivedIfExists(options);
        }
        
        if (this.clearHashAfterLogin) location.hash = '';
        
        return true;
    };

    private handleLoginError(options: LoginOptions, parts: object): void {
        var savedNonce = this._storage.getItem("nonce");
        if (options.onLoginError) 
            options.onLoginError(parts)
        if (this.clearHashAfterLogin) location.hash = '';
    }
    
    private processIdToken(idToken: string, accessToken: string): object {
            var tokenParts = idToken.split(".");
            var headerBase64 = this.padBase64(tokenParts[0]);
            var headerJson = Base64.decode(headerBase64);
            var claimsBase64 = this.padBase64(tokenParts[1]);
            var claimsJson = Base64.decode(claimsBase64);
            var claims = JSON.parse(claimsJson);
            var savedNonce = this._storage.getItem("nonce");
            
            if (Array.isArray(claims.aud)) {
                if (claims.aud.every(v => v !== this.clientId)) {
                    console.warn("Wrong audience: " + claims.aud.join(","));
                    return null;
                }
            } else {
                if (claims.aud !== this.clientId) {
                    console.warn("Wrong audience: " + claims.aud);
                    return null;
                }
            }

            if (this.issuer && claims.iss !== this.issuer) {
                console.warn("Wrong issuer: " + claims.iss);
                return null;
            }

            if (claims.nonce !== savedNonce) {
                console.warn("Wrong nonce: " + claims.nonce);
                return null;
            }
            
            if (accessToken && !this.checkAtHash(accessToken, claims)) {
                console.warn("Wrong at_hash");
                return null;
            }
            
            var now = Date.now();
            var issuedAtMSec = claims.iat * 1000;
            var expiresAtMSec = claims.exp * 1000;
            
            var tenMinutesInMsec = 1000 * 60 * 10;

            if (issuedAtMSec - tenMinutesInMsec >= now  || expiresAtMSec + tenMinutesInMsec <= now) {
                console.warn("Token has been expired");
                console.warn({
                    now: now,
                    issuedAtMSec: issuedAtMSec,
                    expiresAtMSec: expiresAtMSec
                });
                return null;
            }

            return {
                id_token: idToken,
                id_token_claims_obj: claimsJson,
                id_token_header_obj: headerJson,
                id_token_expires_at: expiresAtMSec
            };
    }
    
    getIdentityClaims(): object {
        var claims = this._storage.getItem("id_token_claims_obj");
        if (!claims) return null;
        return JSON.parse(claims);
    }
    
    getIdToken(): string {
        return this._storage.getItem("id_token");
    }
    
    private padBase64(base64data): string {
        while (base64data.length % 4 !== 0) {
            base64data += "=";
        }
        return base64data;
    }

    getAccessToken(): string {
        return this._storage.getItem("access_token");
    };

    getAccessTokenExpiration(): number {
        return parseInt(this._storage.getItem("expires_at"));
    }

    getIdTokenExpiration(): number {
        return parseInt(this._storage.getItem("id_token_expires_at"));
    }

    hasValidAccessToken(): boolean {
        if (this.getAccessToken()) {

            var expiresAt = this._storage.getItem("expires_at");
            var now = new Date();
            if (expiresAt && parseInt(expiresAt) < now.getTime()) {
                return false;
            }

            return true;
        }

        return false;
    };
    
    hasValidIdToken(): boolean {
        if (this.getIdToken()) {

            var expiresAt = this._storage.getItem("id_token_expires_at");
            var now = new Date();
            if (expiresAt && parseInt(expiresAt) < now.getTime()) {
                return false;
            }

            return true;
        }

        return false;
    };
    
    authorizationHeader(): string {
        return "Bearer " + this.getAccessToken();
    }
    
    logOut(noRedirectToLogoutUrl: boolean = false): void {
        var id_token = this.getIdToken();
        this._storage.removeItem("access_token");
        this._storage.removeItem("id_token");
        this._storage.removeItem("refresh_token");
        this._storage.removeItem("nonce");
        this._storage.removeItem("expires_at");
        this._storage.removeItem("id_token_claims_obj");
        this._storage.removeItem("id_token_expires_at");
        
        if (!this.logoutUrl) return;
        if (noRedirectToLogoutUrl) return;
        if (!id_token) return;

        let logoutUrl: string;
        
        // For backward compatibility
        if (this.logoutUrl.indexOf('{{') > -1) {
            logoutUrl = this.logoutUrl.replace(/\{\{id_token\}\}/, id_token);
        }
        else {
            logoutUrl = this.logoutUrl + "?id_token_hint=" 
                                + encodeURIComponent(id_token)
                                + "&post_logout_redirect_uri="
                                + encodeURIComponent(this.postLogoutRedirectUri || this.redirectUri);
        }
        location.href = logoutUrl;
    };

    private createAndSaveNonce(): Promise<string> {
        var that = this;
        return this.createNonce().then(function (nonce: any) {
            that._storage.setItem("nonce", nonce);
            return nonce;
        })
    };

    private createNonce(): Promise<string> {
        
        return new Promise((resolve, reject) => { 
        
            if (this.rngUrl) {
                throw new Error("createNonce with rng-web-api has not been implemented so far");
            }
            else {
                var text = "";
                var possible = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

                for (var i = 0; i < 40; i++)
                    text += possible.charAt(Math.floor(Math.random() * possible.length));
                
                resolve(text);
            }
        
        });
    };

    private getFragment(): object {
        if (window.location.hash.indexOf("#") === 0) {
            return this.parseQueryString(window.location.hash.substr(1));
        } else {
            return {};
        }
    };

    private parseQueryString(queryString: string): object {
        var data = {}, pairs, pair, separatorIndex, escapedKey, escapedValue, key, value;

        if (queryString === null) {
            return data;
        }

        pairs = queryString.split("&");

        for (var i = 0; i < pairs.length; i++) {
            pair = pairs[i];
            separatorIndex = pair.indexOf("=");

            if (separatorIndex === -1) {
                escapedKey = pair;
                escapedValue = null;
            } else {
                escapedKey = pair.substr(0, separatorIndex);
                escapedValue = pair.substr(separatorIndex + 1);
            }

            key = decodeURIComponent(escapedKey);
            value = decodeURIComponent(escapedValue);

            if (key.substr(0, 1) === '/')
                key = key.substr(1);

            data[key] = value;
        }

        return data;
    };

    private checkAtHash(accessToken: string, idClaims: object): boolean {
        if (!accessToken || !idClaims || !idClaims['at_hash'] ) return true;
        var tokenHash: Array<any> = sha256(accessToken, { asBytes: true });
        var leftMostHalf = tokenHash.slice(0, (tokenHash.length/2) );
        var tokenHashBase64 = fromByteArray(leftMostHalf);
        var atHash = tokenHashBase64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
        var claimsAtHash = idClaims['at_hash'].replace(/=/g, "");
        var atHash = tokenHashBase64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");

        if (atHash != claimsAtHash) {
            console.error("exptected at_hash: " + atHash);    
            console.error("actual at_hash: " + claimsAtHash);
        }
        
        return (atHash == claimsAtHash);
    }
    
}
