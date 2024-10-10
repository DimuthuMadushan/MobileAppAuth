import ballerina/http;
import ballerina/log;

configurable MobileAppConfig mobileConfig = ?;

final http:Client mobileApp = check new (mobileConfig.appUrl,
    auth = {
        tokenUrl: mobileConfig.tokenUrl,
        clientId: mobileConfig.clientId,
        clientSecret: mobileConfig.clientSecret
    }
);

isolated function extractGrantType(RequestParams[] params) returns GrantType|error {
    string? grantType = ();
    string? twoFa = ();
    string? authSessionId = ();
    string? deviceId = ();
    string? twoFaType = ();
    string? tokenSerialNo = ();
    string? tokenResponse = ();
    string? apiVersion = ();
    foreach RequestParams param in params {
        string[]? value = param.values;
        if value is () {
            continue;
        }
        match param.name {
            GRANT_TYPE => {
                grantType = value[0];
            }
            TWO_FA => {
                twoFa = value[0];
            }
            AUTH_SESSION_ID => {
                authSessionId = value[0];
            }
            DEVICE_ID => {
                deviceId = value[0];
            }
            TWO_FA_TYPE => {
                twoFaType = value[0];
            }
            TOKEN_SERIAL_NO => {
                tokenSerialNo = value[0];
            }
            TOKEN_RESPONSE => {
                tokenResponse = value[0];
            }
            API_VERSION => {
                apiVersion = value[0];
            }
        }
    }
    if grantType is () {
        return error("Grant type is not provided");
    } else if grantType == TWO_FA_OTP && twoFa is string && authSessionId is string && deviceId is string &&
        twoFaType is string {
        return {twoFa, authSessionId, deviceId, twoFaType};
    } else if grantType == SOFT_TOKEN_OTP && authSessionId is string && tokenSerialNo is string &&
        tokenResponse is string {
        return {authSessionId, tokenSerialNo, tokenResponse};
    } else if grantType == ALWAYS_TWO_FA_OTP && twoFa is string && authSessionId is string && deviceId is string &&
        twoFaType is string && tokenSerialNo is string && tokenResponse is string && apiVersion is string {
        return <AlwaysTwoFaOtpGrant>{twoFa, authSessionId, deviceId, twoFaType, tokenSerialNo, tokenResponse, apiVersion};
    } else {
        return error(string `Required parameters are not provided for ${grantType} grant type`);
    }
}

isolated function handleTwoFaOtpGrant(TwoFaOtpGrant payload) returns SuccessResponseOk|ErrorResponseBadRequest|ErrorResponseInternalServerError {
    do {
        log:printInfo("TwoFaOtpGrant: " + payload.toJsonString());
        record {string userId;} response = check mobileApp->/twofaotp/authentication.get(
            otp = payload.twoFa,
            sessionId = payload.authSessionId,
            deviceId = payload.deviceId,
            twoFaType = payload.twoFaType
        );
        log:printInfo("User ID: " + response.toJsonString());
        return <SuccessResponseOk>{body: {actionStatus: SUCCESS, "userId": response.userId}};
    } on fail error err {
        log:printError("Authentication failed for TwoFaOtp grant type: ", err);
        return <ErrorResponseInternalServerError>{body: {actionStatus: ERROR, 'error: err.message()}};
    }
}

isolated function handleSoftTokenOtpGrant(SoftTokenOtpGrant payload) returns SuccessResponseOk|ErrorResponseBadRequest|ErrorResponseInternalServerError {
    do {
        log:printInfo("SoftTokenGrant: " + payload.toJsonString());
        record {string userId;} response = check mobileApp->/softtoken/authentication.get(
            tokenResponse = payload.tokenResponse,
            authSessionId = payload.authSessionId,
            tokenSerialNumber = payload.tokenSerialNo
        );
        log:printInfo("User ID: " + response.toJsonString());
        return <SuccessResponseOk>{body: {actionStatus: SUCCESS, "userId": response.userId}};
    } on fail error err {
        log:printError("Authentication failed for SoftTokenOtp grant type: ", err);
        return <ErrorResponseInternalServerError>{body: {actionStatus: ERROR, 'error: err.message()}};
    }
}

isolated function handleAlwaysTwoFaOtpGrant(AlwaysTwoFaOtpGrant payload) returns SuccessResponseOk|ErrorResponseBadRequest|ErrorResponseInternalServerError {
    do {
        log:printInfo("AlwaysTwoFaOtpGrant: " + payload.toJsonString());
        record {string userId;} response = check mobileApp->/alwaystwofaotp/authentication.get(
            otp = payload.twoFa,
            authSessionId = payload.authSessionId,
            deviceId = payload.deviceId,
            twoFaType = payload.twoFaType,
            tokenSerialNumber = payload.tokenSerialNo,
            tokenResponse = payload.tokenResponse
        );
        log:printInfo("User ID: " + response.toJsonString());
        return <SuccessResponseOk>{body: {actionStatus: SUCCESS, "userId": response.userId}};
    } on fail error err {
        log:printError("Authentication failed for AlwaysTwoFaOtp grant type: ", err);
        return <ErrorResponseInternalServerError>{body: {actionStatus: ERROR, 'error: err.message()}};
    }
}
