import ballerina/http;

public type SuccessResponseOk record {|
    *http:Ok;
    SuccessResponseBody body;
|};

# Defines the success response.
public type SuccessResponse record {
    SUCCESS actionStatus;
    Operations[] operations;
};

public type ErrorResponseBadRequest record {|
    *http:BadRequest;
    ErrorResponse body;
|};

# Contains information about the authenticated user associated with the token request.
public type User record {
    # Defines the unique identifier of the user.
    string id?;
};

# Refers to the organization to which the user belongs. Organizations represent partners/enterprise customers in Business-to-Business (B2B) use cases.
public type Organization record {
    # The unique identifier of the organization.
    string id?;
    # Name of the organization used to identify the organization in configurations, user interfaces, etc.
    string name?;
};

# Defines the add operation.
public type addOperation AllowedOperation;

# Any additional parameters included in the access token request. These may be custom parameters defined by the client or necessary for specific flows. All request parameters are not incorporated, specially sensitive parameters like client secret, username and password, etc..
public type Request record {
    # The type of OAuth2 grant used for the token request, such as authorization code, client credentials, password, or refresh token. This defines the flow that is being used to obtain the access token.
    string grantType?;
    # The unique identifier of the client (application) that is requesting the access token.
    string clientId?;
    # The scopes requested by the client, which define the permissions associated with the access token. Scopes determine what resources the access token will grant access to.
    string[] scopes?;
    # Any additional HTTP headers included in the access token request. These may contain custom information or metadata that the client has sent. All headers in request are not incorporated specially sensitive headers like ‘Authorization’, ‘Cookie’, etc.
    RequestHeaders[] additionalHeaders?;
    RequestParams[] additionalParams?;
};

public type RequestParams record {
    string name?;
    string[] value?;
};

public type AccessTokenClaims record {
    string name?;
    string|int|boolean|string[] value?;
};

# Defines the replace operation.
public type replaceOperation AllowedOperation;

# When the external service responds with an ERROR state, it can return an HTTP status code of 400, 401, or 500, indicating either a validation failure or an issue processing the request. 
public type ErrorResponse record {
    # Indicates the outcome of the request. For an error operation, this should be set to ERROR.
    ERROR actionStatus?;
    # The cause of the error.
    string errorMessage?;
    # A detailed description of the error.
    string errorDescription?;
};

# This property represents the tenant under which the token request is being processed.
public type Tenant record {
    # The unique numeric identifier of the tenant.
    string id?;
    # The domain name of the tenant.
    string name?;
};

# Indicates the user store in which the user's data is being managed.
public type UserStore record {
    # The unique identifier for the user store.
    string id?;
    # User store name used to identify the user store in configuration settings, user interfaces, and administrative tasks.
    string name?;
};

public type ErrorResponseInternalServerError record {|
    *http:InternalServerError;
    ErrorResponse body;
|};

# Defines the remove operation.
public type removeOperation AllowedOperation;

# Represents the access token that is about to be issued. It contains claims and scopes, of the access token which can then be modified by your external service based on the logic implemented in the pre-issue access token action.
public type AccessToken record {
    # An array that contains both standard access token claims and any OpenID Connect (OIDC) claims configured to be included in the access token.
    # 
    # Standard claims:
    # 
    # - **sub**: The subject identifier for the token, typically representing the user. In M2M apps that use client credentials this represents the application.
    # - **iss**: The issuer of the token, which is the tenant of Asgardeo that acts as the authorization server.
    # - **aud**: The audience for the token.
    # - **client_id**: The identifier of the client (application) that requested the token.
    # - **aut**: The authorized user type associated with the token.
    # 
    #   Can have the following values:
    #   - **APPLICATION**: Indicates that the token is authorized for an application.
    #   - **APPLICATION_USER**: Indicates that the token is authorized for a user.
    # 
    # - **expires_in**: The duration (in seconds) for which the token is valid.
    # - **binding_type**: Indicates the type of binding associated with the token, if applicable.
    # - **binding_ref**: A reference identifier for the binding, if applicable.
    # - **subject_type**: Specifies the type of subject (e.g., public or pairwise) as per OIDC specifications.
    # 
    #   OIDC claims are any additional claims configured in the application to be included in the access token. These claims are based on the OIDC standard and may include user profile information such as email, given-name, or custom claims specific to the application. 
    AccessTokenClaims[] claims?;
    # Lists the permissions or access levels granted by the access token.
    string[] scopes?;
};

public type FailedResponse record {
    # Indicates the outcome of the request. For a failed operation, this should be set to FAILED.
    FAILED actionStatus;
    # Provides the reason for failing to issue an access token.
    string failureReason;
    # Offers a detailed explanation of the failure.
    string failureDescription;
};

# Defines the set of operations that your external service is permitted to perform on the access token's claims and scopes.
public type AllowedOperations (addOperation|replaceOperation|removeOperation)[];

# Defines the context data related to the pre issue access token event that needs to be shared with the custom service to process and execute.
public type Event record {
    Request request?;
    Tenant tenant?;
    User user?;
    Organization organization?;
    UserStore userStore?;
    AccessToken accessToken?;
};

# Defines the operation
public type AllowedOperation record {
    "add"|"replace"|"remove" op?;
    string[] paths?;
};

public type SuccessResponseBody SuccessResponse|FailedResponse;

public type RequestHeaders record {
    string name?;
    string[] values?;
};

public type Operations record {
    string op?;
    string path?;
    OperationValue value?;
};

public type OperationValue record {
    string name;
    string value;
};

public type RequestBody record {
    # A unique correlation identifier that associates with the token request received by Asgardeo
    string requestId?;
    # Specifies the action being triggered, which in this case is PRE_ISSUE_ACCESS_TOKEN.
    PRE_ISSUE_ACCESS_TOKEN actionType?;
    Event event?;
    AllowedOperations allowedOperations?;
};

type TwoFaOtpPayload record {|
    string twoFa;
    string authSessionId;
    string deviceId;
    string twoFaType;
|};

enum actionType {
    PRE_ISSUE_ACCESS_TOKEN
};

type GrantType TwoFaOtpGrant|SoftTokenOtpGrant|AlwaysTwoFaOtpGrant;

type TwoFaOtpGrant record {
    string twoFa;
    string authSessionId;
    string deviceId;
    string twoFaType;
};

type SoftTokenOtpGrant record {
    string authSessionId;
    string tokenSerialNo;
    string tokenResponse;
};

type AlwaysTwoFaOtpGrant record {
    string twoFa;
    string authSessionId;
    string deviceId;
    string twoFaType;
    string tokenSerialNo;
    string tokenResponse;
    string apiVersion;
};

enum AuthParamNames {
    GRANT_TYPE = "grantType",
    TWO_FA = "twoFa",
    AUTH_SESSION_ID = "authSessionId",
    DEVICE_ID = "deviceId",
    TWO_FA_TYPE = "twoFaType",
    TOKEN_SERIAL_NO = "tokenSerialNo",
    TOKEN_RESPONSE = "tokenResponse",
    API_VERSION = "apiVersion"
};

enum OtpTypes {
    TWO_FA_OTP = "twoFaOtp",
    SOFT_TOKEN_OTP = "softTokenOtp",
    ALWAYS_TWO_FA_OTP = "alwaysTwoFaOtp"
};

enum ActionStatus {
    SUCCESS,
    ERROR,
    FAILED
};

type MobileAppConfig record {|
    string appUrl;
    string tokenUrl;
    string clientId;
    string clientSecret;
|};
