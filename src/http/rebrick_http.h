#ifndef __REBRICK_HTTP_H__
#define __REBRICK_HTTP_H__

#include "../socket/rebrick_tlssocket.h"
#include "../common/rebrick_buffer.h"
#include "../lib/picohttpparser.h"
#include "../lib/uthash.h"
#include "./nghttp2/nghttp2.h"


#define REBRICK_HTTP_VERSION1 1
#define REBRICK_HTTP_VERSION2 2


#define REBRICK_HTTP_BUFFER_MALLOC 8192

#define REBRICK_HTTP_MAX_HEADER_LEN 8192
#define REBRICK_HTTP_MAX_HEADER_KEY_LEN 128
#define REBRICK_HTTP_MAX_HOSTNAME_LEN 1024
#define REBRICK_HTTP_MAX_URI_LEN 8192
#define REBRICK_HTTP_MAX_PATH_LEN 8192
#define REBRICK_HTTP_MAX_METHOD_LEN 16
#define REBRICK_HTTP_MAX_SCHEME_LEN 16
#define REBRICK_HTTP_MAX_STATUSCODE_LEN 64
#define REBRICK_HTTP_MAX_HEADERS 96




public_ typedef struct rebrick_http_key_value{
    public_ readonly_ char *key;
    public_ size_t keylen;
    public_ readonly_ char *key_lower;
    public_ readonly_ char *value;
    public_ size_t valuelen;
    UT_hash_handle hh;
}rebrick_http_key_value_t;

int32_t rebrick_http_key_value_new(rebrick_http_key_value_t **keyvalue,const char *key,const char *value);
int32_t rebrick_http_key_value_new2(rebrick_http_key_value_t **keyvalue,const void *key,size_t keylen,const void *value,size_t valuelen);
int32_t rebrick_http_key_value_destroy(rebrick_http_key_value_t *keyvalue);

public_ typedef struct rebrick_http_header{
    base_object();
    public_ char path[REBRICK_HTTP_MAX_PATH_LEN];
    public_ char method[REBRICK_HTTP_MAX_METHOD_LEN];
    public_ char scheme[REBRICK_HTTP_MAX_SCHEME_LEN];
    public_ char host[REBRICK_HTTP_MAX_HOSTNAME_LEN];
    public_ int8_t major_version;
    public_ int8_t minor_version;
    public_ int16_t status_code;
    public_ char status_code_str[REBRICK_HTTP_MAX_STATUSCODE_LEN];
    public_ rebrick_http_key_value_t *headers;
    public_ int32_t is_request;
    //http2 supporting
    public_ int32_t stream_id;



}rebrick_http_header_t;


int32_t rebrick_http_header_new(rebrick_http_header_t **header,const char *scheme,const char*host,const char *method,const char *path,int8_t major,int8_t minor);
int32_t rebrick_http_header_new2(rebrick_http_header_t **header,const char *scheme,size_t scheme_len,const char*host,size_t host_len, const void *method,size_t method_len,const void *path,size_t path_len,int8_t major,int8_t minor);
int32_t rebrick_http_header_new3(rebrick_http_header_t **header,int32_t status,const char *status_code,int8_t major,int8_t minor);
int32_t rebrick_http_header_new4(rebrick_http_header_t **header,int32_t status,const void *status_code,size_t status_code_len,int8_t major,int8_t minor);
int32_t rebrick_http_header_new5(rebrick_http_header_t **header,int32_t is_request,int8_t major,int8_t minor);
int32_t rebrick_http_header_add_header(rebrick_http_header_t *header,const char *key,const char*value);
int32_t rebrick_http_header_add_header2(rebrick_http_header_t *header,const uint8_t *key,size_t keylen,const uint8_t *value,size_t valuelen);
int32_t rebrick_http_header_contains_key(rebrick_http_header_t *header,const char *key,int32_t *founded);
int32_t rebrick_http_header_get_header(rebrick_http_header_t *header,const char *key,const char **value);
int32_t rebrick_http_header_remove_key(rebrick_http_header_t *header,const char *key);
int32_t rebrick_http_header_destroy(rebrick_http_header_t *header);
int32_t rebrick_http_header_count(rebrick_http_header_t *header,int32_t *count);
int32_t rebrick_http_header_to_http_buffer(rebrick_http_header_t *header,rebrick_buffer_t **buffer);
int32_t rebrick_http_header_to_http2_buffer(rebrick_http_header_t *header,rebrick_buffer_t **buffer);






/*! Enum for the HTTP status codes.
 */
enum Rebrick_HttpStatus_Code
{
	/*####### 1xx - Informational #######*/
	/* Indicates an interim response for communicating connection status
	 * or request progress prior to completing the requested action and
	 * sending a final response.
	 */
	Rebrick_HttpStatus_Continue           = 100, /*!< Indicates that the initial part of a request has been received and has not yet been rejected by the server. */
	Rebrick_HttpStatus_SwitchingProtocols = 101, /*!< Indicates that the server understands and is willing to comply with the client's request, via the Upgrade header field, for a change in the application protocol being used on this connection. */
	Rebrick_HttpStatus_Processing         = 102, /*!< Is an interim response used to inform the client that the server has accepted the complete request, but has not yet completed it. */
	Rebrick_HttpStatus_EarlyHints         = 103, /*!< Indicates to the client that the server is likely to send a final response with the header fields included in the informational response. */

	/*####### 2xx - Successful #######*/
	/* Indicates that the client's request was successfully received,
	 * understood, and accepted.
	 */
	Rebrick_HttpStatus_OK                          = 200, /*!< Indicates that the request has succeeded. */
	Rebrick_HttpStatus_Created                     = 201, /*!< Indicates that the request has been fulfilled and has resulted in one or more new resources being created. */
	Rebrick_HttpStatus_Accepted                    = 202, /*!< Indicates that the request has been accepted for processing, but the processing has not been completed. */
	Rebrick_HttpStatus_NonAuthoritativeInformation = 203, /*!< Indicates that the request was successful but the enclosed payload has been modified from that of the origin server's 200 (OK) response by a transforming proxy. */
	Rebrick_HttpStatus_NoContent                   = 204, /*!< Indicates that the server has successfully fulfilled the request and that there is no additional content to send in the response payload body. */
	Rebrick_HttpStatus_ResetContent                = 205, /*!< Indicates that the server has fulfilled the request and desires that the user agent reset the \"document view\", which caused the request to be sent, to its original state as received from the origin server. */
	Rebrick_HttpStatus_PartialContent              = 206, /*!< Indicates that the server is successfully fulfilling a range request for the target resource by transferring one or more parts of the selected representation that correspond to the satisfiable ranges found in the requests's Range header field. */
	Rebrick_HttpStatus_MultiStatus                 = 207, /*!< Provides status for multiple independent operations. */
	Rebrick_HttpStatus_AlreadyReported             = 208, /*!< Used inside a DAV:propstat response element to avoid enumerating the internal members of multiple bindings to the same collection repeatedly. [RFC 5842] */
	Rebrick_HttpStatus_IMUsed                      = 226, /*!< The server has fulfilled a GET request for the resource, and the response is a representation of the result of one or more instance-manipulations applied to the current instance. */

	/*####### 3xx - Redirection #######*/
	/* Indicates that further action needs to be taken by the user agent
	 * in order to fulfill the request.
	 */
	Rebrick_HttpStatus_MultipleChoices   = 300, /*!< Indicates that the target resource has more than one representation, each with its own more specific identifier, and information about the alternatives is being provided so that the user (or user agent) can select a preferred representation by redirecting its request to one or more of those identifiers. */
	Rebrick_HttpStatus_MovedPermanently  = 301, /*!< Indicates that the target resource has been assigned a new permanent URI and any future references to this resource ought to use one of the enclosed URIs. */
	Rebrick_HttpStatus_Found             = 302, /*!< Indicates that the target resource resides temporarily under a different URI. */
	Rebrick_HttpStatus_SeeOther          = 303, /*!< Indicates that the server is redirecting the user agent to a different resource, as indicated by a URI in the Location header field, that is intended to provide an indirect response to the original request. */
	Rebrick_HttpStatus_NotModified       = 304, /*!< Indicates that a conditional GET request has been received and would have resulted in a 200 (OK) response if it were not for the fact that the condition has evaluated to false. */
	Rebrick_HttpStatus_UseProxy          = 305, /*!< \deprecated \parblock Due to security concerns regarding in-band configuration of a proxy. \endparblock
	                                         The requested resource MUST be accessed through the proxy given by the Location field. */
	Rebrick_HttpStatus_TemporaryRedirect = 307, /*!< Indicates that the target resource resides temporarily under a different URI and the user agent MUST NOT change the request method if it performs an automatic redirection to that URI. */
	Rebrick_HttpStatus_PermanentRedirect = 308, /*!< The target resource has been assigned a new permanent URI and any future references to this resource ought to use one of the enclosed URIs. [...] This status code is similar to 301 Moved Permanently (Section 7.3.2 of rfc7231), except that it does not allow rewriting the request method from POST to GET. */

	/*####### 4xx - Client Error #######*/
	/* Indicates that the client seems to have erred.
	 */
	Rebrick_HttpStatus_BadRequest                  = 400, /*!< Indicates that the server cannot or will not process the request because the received syntax is invalid, nonsensical, or exceeds some limitation on what the server is willing to process. */
	Rebrick_HttpStatus_Unauthorized                = 401, /*!< Indicates that the request has not been applied because it lacks valid authentication credentials for the target resource. */
	Rebrick_HttpStatus_PaymentRequired             = 402, /*!< *Reserved* */
	Rebrick_HttpStatus_Forbidden                   = 403, /*!< Indicates that the server understood the request but refuses to authorize it. */
	Rebrick_HttpStatus_NotFound                    = 404, /*!< Indicates that the origin server did not find a current representation for the target resource or is not willing to disclose that one exists. */
	Rebrick_HttpStatus_MethodNotAllowed            = 405, /*!< Indicates that the method specified in the request-line is known by the origin server but not supported by the target resource. */
	Rebrick_HttpStatus_NotAcceptable               = 406, /*!< Indicates that the target resource does not have a current representation that would be acceptable to the user agent, according to the proactive negotiation header fields received in the request, and the server is unwilling to supply a default representation. */
	Rebrick_HttpStatus_ProxyAuthenticationRequired = 407, /*!< Is similar to 401 (Unauthorized), but indicates that the client needs to authenticate itself in order to use a proxy. */
	Rebrick_HttpStatus_RequestTimeout              = 408, /*!< Indicates that the server did not receive a complete request message within the time that it was prepared to wait. */
	Rebrick_HttpStatus_Conflict                    = 409, /*!< Indicates that the request could not be completed due to a conflict with the current state of the resource. */
	Rebrick_HttpStatus_Gone                        = 410, /*!< Indicates that access to the target resource is no longer available at the origin server and that this condition is likely to be permanent. */
	Rebrick_HttpStatus_LengthRequired              = 411, /*!< Indicates that the server refuses to accept the request without a defined Content-Length. */
	Rebrick_HttpStatus_PreconditionFailed          = 412, /*!< Indicates that one or more preconditions given in the request header fields evaluated to false when tested on the server. */
	Rebrick_HttpStatus_PayloadTooLarge             = 413, /*!< Indicates that the server is refusing to process a request because the request payload is larger than the server is willing or able to process. */
	Rebrick_HttpStatus_URITooLong                  = 414, /*!< Indicates that the server is refusing to service the request because the request-target is longer than the server is willing to interpret. */
	Rebrick_HttpStatus_UnsupportedMediaType        = 415, /*!< Indicates that the origin server is refusing to service the request because the payload is in a format not supported by the target resource for this method. */
	Rebrick_HttpStatus_RangeNotSatisfiable         = 416, /*!< Indicates that none of the ranges in the request's Range header field overlap the current extent of the selected resource or that the set of ranges requested has been rejected due to invalid ranges or an excessive request of small or overlapping ranges. */
	Rebrick_HttpStatus_ExpectationFailed           = 417, /*!< Indicates that the expectation given in the request's Expect header field could not be met by at least one of the inbound servers. */
	Rebrick_HttpStatus_ImATeapot                   = 418, /*!< Any attempt to brew coffee with a teapot should result in the error code 418 I'm a teapot. */
	Rebrick_HttpStatus_UnprocessableEntity         = 422, /*!< Means the server understands the content type of the request entity (hence a 415(Unsupported Media Type) status code is inappropriate), and the syntax of the request entity is correct (thus a 400 (Bad Request) status code is inappropriate) but was unable to process the contained instructions. */
	Rebrick_HttpStatus_Locked                      = 423, /*!< Means the source or destination resource of a method is locked. */
	Rebrick_HttpStatus_FailedDependency            = 424, /*!< Means that the method could not be performed on the resource because the requested action depended on another action and that action failed. */
	Rebrick_HttpStatus_UpgradeRequired             = 426, /*!< Indicates that the server refuses to perform the request using the current protocol but might be willing to do so after the client upgrades to a different protocol. */
	Rebrick_HttpStatus_PreconditionRequired        = 428, /*!< Indicates that the origin server requires the request to be conditional. */
	Rebrick_HttpStatus_TooManyRequests             = 429, /*!< Indicates that the user has sent too many requests in a given amount of time (\"rate limiting\"). */
	Rebrick_HttpStatus_RequestHeaderFieldsTooLarge = 431, /*!< Indicates that the server is unwilling to process the request because its header fields are too large. */
	Rebrick_HttpStatus_UnavailableForLegalReasons  = 451, /*!< This status code indicates that the server is denying access to the resource in response to a legal demand. */

	/*####### 5xx - Server Error #######*/
	/* Indicates that the server is aware that it has erred
	 * or is incapable of performing the requested method.
	 */
	Rebrick_HttpStatus_InternalServerError           = 500, /*!< Indicates that the server encountered an unexpected condition that prevented it from fulfilling the request. */
	Rebrick_HttpStatus_NotImplemented                = 501, /*!< Indicates that the server does not support the functionality required to fulfill the request. */
	Rebrick_HttpStatus_BadGateway                    = 502, /*!< Indicates that the server, while acting as a gateway or proxy, received an invalid response from an inbound server it accessed while attempting to fulfill the request. */
	Rebrick_HttpStatus_ServiceUnavailable            = 503, /*!< Indicates that the server is currently unable to handle the request due to a temporary overload or scheduled maintenance, which will likely be alleviated after some delay. */
	Rebrick_HttpStatus_GatewayTimeout                = 504, /*!< Indicates that the server, while acting as a gateway or proxy, did not receive a timely response from an upstream server it needed to access in order to complete the request. */
	Rebrick_HttpStatus_HTTPVersionNotSupported       = 505, /*!< Indicates that the server does not support, or refuses to support, the protocol version that was used in the request message. */
	Rebrick_HttpStatus_VariantAlsoNegotiates         = 506, /*!< Indicates that the server has an internal configuration error: the chosen variant resource is configured to engage in transparent content negotiation itself, and is therefore not a proper end point in the negotiation process. */
	Rebrick_HttpStatus_InsufficientStorage           = 507, /*!< Means the method could not be performed on the resource because the server is unable to store the representation needed to successfully complete the request. */
	Rebrick_HttpStatus_LoopDetected                  = 508, /*!< Indicates that the server terminated an operation because it encountered an infinite loop while processing a request with "Depth: infinity". [RFC 5842] */
	Rebrick_HttpStatus_NotExtended                   = 510, /*!< The policy for accessing the resource has not been met in the request. [RFC 2774] */
	Rebrick_HttpStatus_NetworkAuthenticationRequired = 511, /*!< Indicates that the client needs to authenticate to gain network access. */

	Rebrick_HttpStatus_xxx_max = 1023
};

//static char Rebrick_HttpStatus_isInformational(int code) { return (code >= 100 && code < 200); } /*!< \returns \c true if the given \p code is an informational code. */
//static char Rebrick_HttpStatus_isSuccessful(int code)    { return (code >= 200 && code < 300); } /*!< \returns \c true if the given \p code is a successful code. */
//static char Rebrick_HttpStatus_isRedirection(int code)   { return (code >= 300 && code < 400); } /*!< \returns \c true if the given \p code is a redirectional code. */
//static char Rebrick_HttpStatus_isClientError(int code)   { return (code >= 400 && code < 500); } /*!< \returns \c true if the given \p code is a client error code. */
//static char Rebrick_HttpStatus_isServerError(int code)   { return (code >= 500 && code < 600); } /*!< \returns \c true if the given \p code is a server error code. */
//static char Rebrick_HttpStatus_isError(int code)         { return (code >= 400); }               /*!< \returns \c true if the given \p code is any type of error code. */

/*! Returns the standard HTTP reason phrase for a HTTP status code.
 * \param code An HTTP status code.
 * \return The standard HTTP reason phrase for the given \p code or \c NULL if no standard
 * phrase for the given \p code is known.
 */
const char* Rebrick_HttpStatus_ReasonPhrase(int code);




#endif