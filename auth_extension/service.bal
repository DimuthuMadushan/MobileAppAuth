import ballerina/http;
import ballerina/log;

listener http:Listener customAccessTokenEp = new (9091);

isolated service / on customAccessTokenEp {
    isolated resource function post .(@http:Payload json jsonPayload) returns SuccessResponseOk|ErrorResponseBadRequest|ErrorResponseInternalServerError {
        do {
            log:printInfo("Payload: " + jsonPayload.toJsonString());
            RequestBody payload = check jsonPayload.fromJsonWithType();
            if payload.actionType == "PRE_ISSUE_ACCESS_TOKEN" {
                string grantType = payload.event?.request?.grantType.toString();
                if grantType == "twofaotp" {
                    log:printInfo("Grant type twofaotp is supported");
                    Request request = check payload.event?.request.ensureType();
                    log:printInfo("Request: " + request.toJsonString());
                    return handleTwoFaOtp(request);
                } else if grantType == "alwaystwofagrantotp" {
                    log:printInfo("Grant type alwaystwofagrantotp is not supported");
                    return <ErrorResponseBadRequest>{body: {errorDescription: "Grant type alwaystwofagrantotp is not supported"}};
                } else if grantType == "softtokenotp" {
                    log:printInfo("Grant type softtokenotp is not supported");
                    return <ErrorResponseBadRequest>{body: {errorDescription: "Grant type softtokenotp is not supported"}};
                }
                log:printInfo("Invalid grant type");
                return <ErrorResponseBadRequest>{body: {errorDescription: "Invalid grant type"}};
            }
            log:printInfo("Action type is not PRE_ISSUE_ACCESS_TOKEN");
            return <ErrorResponseBadRequest>{body: {errorDescription: "Invalid action type"}};
        } on fail error err {
            log:printError("Error: ", err);
            return <ErrorResponseBadRequest>{body: {errorDescription: err.message()}};
        }
    }
}
