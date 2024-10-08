import ballerina/http;

listener http:Listener customAccessTokenEp = new (9091);

isolated service / on customAccessTokenEp {
    isolated resource function post .(@http:Payload RequestBody payload) returns SuccessResponseOk|ErrorResponseBadRequest|ErrorResponseInternalServerError {
        do {
            if payload.actionType == "PRE_ISSUE_ACCESS_TOKEN" {
                string grantType = payload.event?.request?.grantType.toString();
                if grantType == "twofaotp" {
                    Request request = check payload.event?.request.ensureType();
                    return handleTwoFaOtp(request);
                } else if grantType == "alwaystwofagrantotp" {
                    return <ErrorResponseBadRequest>{body: {errorDescription: "Grant type alwaystwofagrantotp is not supported"}};
                } else if grantType == "softtokenotp" {
                    return <ErrorResponseBadRequest>{body: {errorDescription: "Grant type softtokenotp is not supported"}};
                }
                return <ErrorResponseBadRequest>{body: {errorDescription: "Invalid grant type"}};
            }
            return <ErrorResponseBadRequest>{body: {errorDescription: "Invalid action type"}};
        } on fail error err {
            return <ErrorResponseBadRequest>{body: {errorDescription: err.message()}};
        }
    }
}
