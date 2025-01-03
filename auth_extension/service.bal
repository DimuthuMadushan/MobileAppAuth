import ballerina/auth;
import ballerina/http;
import ballerina/log;

auth:FileUserStoreConfig fileUserStoreConfig = {};

@http:ServiceConfig {
    auth:[
        {
            fileUserStoreConfig: fileUserStoreConfig
        }
    ]
}
isolated service / on new http:Listener(9091) {
    isolated resource function post .(@http:Payload json jsonPayload) returns SuccessResponseOk|ErrorResponseBadRequest|ErrorResponseInternalServerError {
        do {
            log:printInfo("Payload: " + jsonPayload.toJsonString());
            RequestBody payload = check jsonPayload.fromJsonWithType();
            if payload.actionType == PRE_ISSUE_ACCESS_TOKEN {
                RequestParams[]? requestParams = payload.event?.request?.additionalParams;
                if requestParams is () {
                    string msg = "Token grant type is not provided";
                    log:printInfo(msg);
                    SuccessResponseOk resp = {body: {actionStatus: FAILED, failureReason: msg, failureDescription: msg}};
                    log:printInfo("Service Response: " + resp.toString());
                    return resp;
                }
                GrantType extractGrantTypeResult = check extractGrantType(requestParams);
                if extractGrantTypeResult is TwoFaOtpGrant {
                    return handleTwoFaOtpGrant(extractGrantTypeResult);
                } else if extractGrantTypeResult is SoftTokenOtpGrant {
                    return handleSoftTokenOtpGrant(extractGrantTypeResult);
                }
                return handleAlwaysTwoFaOtpGrant(<AlwaysTwoFaOtpGrant>extractGrantTypeResult);
            }
            string msg = string `Invalid action type ${payload.actionType.toJsonString()} provided`;
            log:printInfo(msg);
            return <SuccessResponseOk>{body: {actionStatus: FAILED, failureReason: msg, failureDescription: "support only PRE_ISSUE_ACCESS_TOKEN action type"}};
        } on fail error err {
            log:printError("Error: ", err);
            ErrorResponseBadRequest resp = {body: {actionStatus: ERROR, errorMessage: "Something went wrong while processing the request", errorDescription: err.message()}};
            log:printInfo("Service Response: " + resp.toString());
            return resp;
        }
    }
}
