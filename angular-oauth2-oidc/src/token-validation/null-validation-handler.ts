import { ValidationHandler, AbstractValidationHandler, ValidationParams } from "./validation-handler";

export class NullValidationHandler implements ValidationHandler {
    validateSignature(validationParams: ValidationParams): Promise<any> {
        return Promise.resolve(null);
    }
    validateAtHash(validationParams: ValidationParams): boolean {
        return true;
    }
}