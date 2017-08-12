import { ValidationHandler } from "./validation-handler";

export const NullValidationHandler: ValidationHandler = function(params) {
    console.warn('No ValidationHandler set. Set one using the property validationHandler.');
    return Promise.resolve();
}