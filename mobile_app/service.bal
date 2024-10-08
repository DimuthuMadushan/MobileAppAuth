import ballerina/http;
import ballerina/log;

isolated service /mobile on new http:Listener(9090) {

    isolated resource function get images/[int page](@http:Header {name: "jwt-assertion"} string? jwt, http:RequestContext ctx) returns json|http:BadRequest {
        ctx.set("jwt-assertion", jwt);
        if page < 0 {
            return <http:BadRequest>{body: "Invalid page number"};
        }
        json images = [{id: 1, name: "image1"}, {id: 2, name: "image2"}];
        return images;
    }

    isolated resource function get twofaotp/authentication(string otp, string sessionId, string deviceId, string twoFaType) returns json|http:BadRequest {
        if otp == "" || sessionId == "" || deviceId == "" || twoFaType == "" {
            return <http:BadRequest>{body: "Invalid request params found"};
        } else if int:fromString(otp) is error {
            return <http:BadRequest>{body: "Invalid OTP provided"};
        }
        log:printInfo("OTP: " + otp);
        log:printInfo("sessionId: " + sessionId);
        json user = {userId: otp};
        return user;
    }

    isolated resource function get alwaystwofaotp/authentication(string otp, string authSessionId, string deviceId, string twoFaType, string tokenSerialNo, string tokenResponse) returns json|http:BadRequest {
        if otp == "" || authSessionId == "" || deviceId == "" || twoFaType == "" {
            return <http:BadRequest>{body: "Invalid request params found"};
        } else if int:fromString(otp) is error {
            return <http:BadRequest>{body: "Invalid OTP provided"};
        }
        log:printInfo("OTP: " + otp);
        log:printInfo("sessionId: " + authSessionId);
        json user = {userId: otp};
        return user;
    }

    isolated resource function get softtoken/authentication(string tokenResponse, string authSessionId, string tokenSerialNumber) returns json|http:BadRequest {
        if tokenResponse == "" || authSessionId == "" || tokenSerialNumber == "" {
            return <http:BadRequest>{body: "Invalid request params found"};
        } else if int:fromString(tokenSerialNumber) is error {
            return <http:BadRequest>{body: "Invalid OTP provided"};
        }
        log:printInfo("OTP: " + tokenSerialNumber);
        log:printInfo("sessionId: " + authSessionId);
        json user = {userId: tokenSerialNumber};
        return user;
    }
}
