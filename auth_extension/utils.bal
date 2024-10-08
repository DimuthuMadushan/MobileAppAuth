import ballerina/http;
import ballerina/log;

configurable string mobileAppUrl = ?;

final http:Client mobileApp = check new (mobileAppUrl);

isolated function getValidUser(TwoFaOtpPayload payload) returns SuccessResponseOk|ErrorResponseBadRequest|ErrorResponseInternalServerError {
    do {
        record {string userId;} response = check mobileApp->/twofaotp/authenitication.get(
            otp = payload.twoFa.toString(),
            sessionId = payload.authSessionId.toString(),
            deviceId = payload.deviceId.toString(),
            twoFaType = payload.twoFaType.toString()
        );
        return <SuccessResponseOk>{body: {actionStatus: "SUCCESS", "userId": response.userId}};
    } on fail error err {
        log:printError("Error: ", err);
        return <ErrorResponseInternalServerError>{body: {actionStatus: "ERROR", 'error: err.message()}};
    }
}

isolated function handleTwoFaOtp(Request request) returns SuccessResponseOk|ErrorResponseBadRequest|ErrorResponseInternalServerError {
    do {
        RequestParams[] params = check request.additionalParams.ensureType();
        TwoFaOtpPayload twoFaOtpPayload = {
            twoFa: "",
            authSessionId: "",
            deviceId: "",
            twoFaType: ""
        };
        foreach RequestParams param in params {
            if param.name == "twofa" && param.values is string[] {
                string[] values = <string[]>param.values;
                if values.length() > 0 {
                    twoFaOtpPayload.twoFa = values[0].toString();
                    continue;
                }
                return <ErrorResponseBadRequest>{body: {errorDescription: "OTP is required"}};
            } else if param.name == "authSessionId" && param.values is string[] {
                string[] values = <string[]>param.values;
                if values.length() > 0 {
                    twoFaOtpPayload.authSessionId = values[0].toString();
                    continue;
                }
                return <ErrorResponseBadRequest>{body: {errorDescription: "Auth Session Id is required"}};
            } else if param.name == "deviceId" && param.values is string[] {
                string[] values = <string[]>param.values;
                if values.length() > 0 {
                    twoFaOtpPayload.deviceId = values[0].toString();
                    continue;
                }
                return <ErrorResponseBadRequest>{body: {errorDescription: "Device ID is required"}};
            } else if param.name == "twoFaType" && param.values is string[] {
                string[] values = <string[]>param.values;
                if values.length() > 0 {
                    twoFaOtpPayload.twoFaType = values[0].toString();
                    continue;
                }
                return <ErrorResponseBadRequest>{body: {errorDescription: "Two Fa Type is required"}};
            }
        }
        return getValidUser(twoFaOtpPayload);
    } on fail error err {
        return <ErrorResponseBadRequest>{body: {errorDescription: err.message()}};
    }
}
