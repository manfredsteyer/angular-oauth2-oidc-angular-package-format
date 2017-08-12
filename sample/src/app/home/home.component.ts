import { Component, OnInit } from '@angular/core';
import {OAuthService} from "angular-oauth2-oidc";

@Component({
    template: `
        <h1 *ngIf="!givenName">Willkommen!</h1>
        <h1 *ngIf="givenName">Willkommen, {{givenName}}!</h1>
        
        <div class="panel panel-default">
            <div class="panel-body">
                <p>Login with Authorization Server</p>
                <button class="btn btn-default" (click)="login()">Login</button>
                <button class="btn btn-default" (click)="logout()">Logout</button>
            </div>
        </div>

        <div class="panel panel-default">
            <div class="panel-body">
                <p>Login with Username/Password</p>

                <p style="color:red; font-weight:bold" *ngIf="loginFailed">
                    Login wasn't successfull.
                </p>

                <div class="form-group">
                    <label>Username</label>
                    <input class="form-control" [(ngModel)]="userName">
                </div>
                <div class="form-group">
                    <label>Password</label>
                    <input class="form-control" type="password" [(ngModel)]="password">
                </div>
                <div class="form-group">
                    <button class="btn btn-default" (click)="loginWithPassword()">Login</button>
                    <button class="btn btn-default" (click)="logout()">Logout</button>
                </div>        
            </div>
        </div>

        <div class="panel panel-default">
            <div class="panel-body">
                <b>Username/Password:</b> max/geheim
            </div>
        </div>

        <div class="panel panel-default">
            <div class="panel-body">
                <p>
                    <b>access_token_expiration:</b> {{access_token_expiration}}
                </p>
                <p>
                    <b>id_token_expiration:</b> {{id_token_expiration}}
                </p>
            </div>
        </div>

        <div class="panel panel-default">
        <div class="panel-body">
            <p>
                <b>access_token:</b> {{access_token}}
            </p>
            <p>
                <b>id_token:</b> {{id_token}}
            </p>
        </div>
    </div>

        <button class="btn btn-default" (click)="testSilentRefresh()">Test silent refresh</button>

    `
})
export class HomeComponent implements OnInit {

    userName: string;
    password: string;
    loginFailed: boolean = false;

    constructor(private oauthService: OAuthService) {
    }

    login() {
        this.oauthService.clientId = "spa-demo";

        this.oauthService.initImplicitFlow();
    }

    logout() {
        this.oauthService.logOut();
    }

    get givenName() {
        var claims = this.oauthService.getIdentityClaims();
        if (!claims) return null;
        return claims['given_name'];
    }

    testSilentRefresh() {
        this
            .oauthService
            .silentRefresh()
            .then(info => console.debug('refresh ok', info))
            .catch(err => console.error('refresh error', err));
    }

    get id_token() {
        return this.oauthService.getIdToken();
    }

    get access_token() {
        return this.oauthService.getAccessToken();
    }

    get id_token_expiration() {
        return this.oauthService.getIdTokenExpiration();
    }

    get access_token_expiration() {
        return this.oauthService.getAccessTokenExpiration();
    }

    loginWithPassword() {

        this.oauthService.clientId = "demo-resource-owner";

        this
            .oauthService
            .fetchTokenUsingPasswordFlowAndLoadUserProfile(this.userName, this.password)
            .then(() => {
                console.debug('successfully logged in');
                this.loginFailed = false;
            })
            .catch((err) => {
                console.error('error logging in', err);
                this.loginFailed = true;
            });
    }

    ngOnInit() { }

}