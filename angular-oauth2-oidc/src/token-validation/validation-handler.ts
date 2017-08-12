export interface ValidationParams {
    idToken: string;
    accessToken: string;
    idTokenHeader?: object;
    jwks?: object;
}

export type ValidationHandler = (validationParams: ValidationParams) => Promise<any>;