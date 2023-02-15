/*
 *  Copyright 2020 F5 Networks
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

import aws from "./aws_common.js"

_require_env_var('S3_BUCKET_NAME');
_require_env_var('S3_SERVER');
_require_env_var('S3_SERVER_PROTO');
_require_env_var('S3_SERVER_PORT');
_require_env_var('S3_REGION');
_require_env_var('AWS_SIGS_VERSION');
_require_env_var('S3_STYLE');

const mod_hmac = require('crypto');

/**
 * Flag indicating debug mode operation. If true, additional information
 * about signature generation will be logged.
 * @type {boolean}
 */
const ALLOW_LISTING = aws.parseBoolean(process.env['ALLOW_DIRECTORY_LIST']);
const PROVIDE_INDEX_PAGE = aws.parseBoolean(process.env['PROVIDE_INDEX_PAGE']);
const APPEND_SLASH = aws.parseBoolean(process.env['APPEND_SLASH_FOR_POSSIBLE_DIRECTORY']);
const FOUR_O_FOUR_ON_EMPTY_BUCKET = aws.parseBoolean(process.env['FOUR_O_FOUR_ON_EMPTY_BUCKET']);
const S3_STYLE = process.env['S3_STYLE'];

const ADDITIONAL_HEADER_PREFIXES_TO_STRIP = _parseArray(process.env['HEADER_PREFIXES_TO_STRIP']);

/**
 * Default filename for index pages to be read off of the backing object store.
 * @type {string}
 */
const INDEX_PAGE = "www/index.html";

/**
 * The current moment as a timestamp. This timestamp will be used across
 * functions in order for there to be no variations in signatures.
 * @type {Date}
 */
const NOW = new Date();

/**
 * Constant defining the service requests are being signed for.
 * @type {string}
 */
const SERVICE = 's3';

/**
 * Transform the headers returned from S3 such that there isn't information
 * leakage about S3 and do other tasks needed for appropriate gateway output.
 * @param r HTTP request
 */
function editHeaders(r) {
    const isDirectoryHeadRequest =
        ALLOW_LISTING &&
        r.method === 'HEAD' &&
        _isDirectory(decodeURIComponent(r.variables.uri_path));

    /* Strips all x-amz- headers from the output HTTP headers so that the
     * requesters to the gateway will not know you are proxying S3. */
    if ('headersOut' in r) {
        for (const key in r.headersOut) {
            /* We delete all headers when it is a directory head request because
             * none of the information is relevant for passing on via a gateway. */
            if (isDirectoryHeadRequest) {
                delete r.headersOut[key];
            } else if (_isHeaderToBeStripped(key.toLowerCase(), ADDITIONAL_HEADER_PREFIXES_TO_STRIP)) {
                delete r.headersOut[key];
            }
        }

        /* Transform content type returned on HEAD requests for directories
         * if directory listing is enabled. If you change the output format
         * for the XSL stylesheet from HTML to something else, you will
         * want to change the content type below. */
        if (isDirectoryHeadRequest) {
            r.headersOut['Content-Type'] = 'text/html; charset=utf-8'
        }
    }
}

/**
 * Determines if a given HTTP header should be removed before being
 * sent on to the requesting client.
 * @param headerName {string} Lowercase HTTP header name
 * @param additionalHeadersToStrip {Array[string]} array of additional headers to remove
 * @returns {boolean} true if header should be removed
 */
function _isHeaderToBeStripped(headerName, additionalHeadersToStrip) {
    if (headerName.indexOf('x-amz-', 0) >= 0) {
        return true;
    }

    for (let i = 0; i < additionalHeadersToStrip.length; i++) {
        const headerToStrip = additionalHeadersToStrip[i];
        if (headerName.indexOf(headerToStrip, 0) >= 0) {
            return true;
        }
    }

    return false;
}

/**
 * Creates an AWS authentication signature based on the global settings and
 * the passed request parameter.
 *
 * @param r {Request} HTTP request object
 * @returns {string} AWS authentication signature
 */
function s3auth(r) {
    const bucket = process.env['S3_BUCKET_NAME'];
    const region = process.env['S3_REGION'];
    let server;
    if (S3_STYLE === 'path') {
        server = process.env['S3_SERVER'] + ':' + process.env['S3_SERVER_PORT'];
    } else {
        server = process.env['S3_SERVER'];
    }
    const sigver = process.env['AWS_SIGS_VERSION'];

    let signature;

    const credentials = aws.readCredentials(r);
    if (sigver == '2') {
        signature = signatureV2(r, bucket, credentials);
    } else {
        signature = signatureV4(r, NOW, bucket, region, server, credentials);
    }

    return signature;
}

/**
 * Build the base file path for a S3 request URI. This function allows for
 * path style S3 URIs to be created that do not use a subdomain to specify
 * the bucket name.
 *
 * @param r {Request} HTTP request object (not used, but required for NGINX configuration)
 * @returns {string} start of the file path for the S3 object URI
 */
function s3BaseUri(r) {
    const bucket = process.env['S3_BUCKET_NAME'];
    let basePath;

    if (S3_STYLE === 'path') {
        aws.debug_log(r, 'Using path style uri : ' + '/' + bucket);
        basePath = '/' + bucket;
    } else {
        basePath = '';
    }

    return basePath;
}

/**
 * Returns the s3 path given the incoming request
 *
 * @param r HTTP request
 * @returns {string} uri for s3 request
 */
function s3uri(r) {
    let uriPath = r.variables.uri_path;
    const basePath = s3BaseUri(r);
    let path;

    // Create query parameters only if directory listing is enabled.
    if (ALLOW_LISTING) {
        const queryParams = _s3DirQueryParams(uriPath, r.method);
        if (queryParams.length > 0) {
            path = basePath + '?' + queryParams;
        } else {
            path = _escapeURIPath(basePath + uriPath);
        }
    } else {
        // This is a path that will resolve to an index page
        if (PROVIDE_INDEX_PAGE  && _isDirectory(uriPath) ) {
            uriPath += INDEX_PAGE;
        }
        path = _escapeURIPath(basePath + uriPath);
    }

    aws.debug_log(r, 'S3 Request URI: ' + r.method + ' ' + path);
    return path;
}

/**
 * Create and encode the query parameters needed to query S3 for an object
 * listing.
 *
 * @param uriPath request URI path
 * @param method request HTTP method
 * @returns {string} query parameters to use with S3 request
 * @private
 */
function _s3DirQueryParams(uriPath, method) {
    if (!_isDirectory(uriPath) || method !== 'GET') {
        return '';
    }

    /* Return if static website. We don't want to list the files in the
       directory, we want to append the index page and get the fil. */
    if (PROVIDE_INDEX_PAGE){
        return '';
    }

    let path = 'delimiter=%2F'

    if (uriPath !== '/') {
        let decodedUriPath = decodeURIComponent(uriPath);
        let without_leading_slash = decodedUriPath.charAt(0) === '/' ?
            decodedUriPath.substring(1, decodedUriPath.length) : decodedUriPath;
        path += '&prefix=' + _encodeURIComponent(without_leading_slash);
    }

    return path;
}

/**
 * Redirects the request to the appropriate location. If the request is not
 * a read (GET/HEAD) request, then we reject the request outright by returning
 * a HTTP 405 error with a list of allowed methods.
 *
 * @param r {Request} HTTP request object
 */
function redirectToS3(r) {
    // This is a read-only S3 gateway, so we do not support any other methods
    if (!(r.method === 'GET' || r.method === 'HEAD')) {
        aws.debug_log(r, 'Invalid method requested: ' + r.method);
        r.internalRedirect("@error405");
        return;
    }

    const uriPath = r.variables.uri_path;
    const isDirectoryListing = ALLOW_LISTING && _isDirectory(uriPath);

    if (isDirectoryListing && r.method === 'GET') {
        r.internalRedirect("@s3Listing");
    } else if ( PROVIDE_INDEX_PAGE == true ) {
        r.internalRedirect("@s3");
    } else if ( !ALLOW_LISTING && !PROVIDE_INDEX_PAGE && uriPath == "/" ) {
       r.internalRedirect("@error404");
    } else {
        r.internalRedirect("@s3");
    }
}

function trailslashControl(r) {
    if (APPEND_SLASH) {
        const hasExtension = /\/[^.\/]+\.[^.]+$/;
        if (!hasExtension.test(r.variables.uri_path)  && !_isDirectory(r.variables.uri_path)){
            return r.internalRedirect("@trailslash");
        }
    }
        r.internalRedirect("@error404");
}

/**
 * Create HTTP Authorization header for authenticating with an AWS compatible
 * v2 API.
 *
 * @param r {Request} HTTP request object
 * @param bucket {string} S3 bucket associated with request
 * @param accessId {string} User access key credential
 * @param secret {string} Secret access key
 * @returns {string} HTTP Authorization header value
 */
function signatureV2(r, bucket, credentials) {
    const method = r.method;
    /* If the source URI is a directory, we are sending to S3 a query string
     * local to the root URI, so this is what we need to encode within the
     * string to sign. For example, if we are requesting /bucket/dir1/ from
     * nginx, then in S3 we need to request /?delimiter=/&prefix=dir1/
     * Thus, we can't put the path /dir1/ in the string to sign. */
    let uri = _isDirectory(r.variables.uri_path) ? '/' : r.variables.uri_path;
    // To return index pages + index.html
    if (PROVIDE_INDEX_PAGE && _isDirectory(r.variables.uri_path)){
        uri = r.variables.uri_path + INDEX_PAGE
    }
    const hmac = mod_hmac.createHmac('sha1', credentials.secretAccessKey);
    const httpDate = aws_common.signedDate(r);
    const stringToSign = method + '\n\n\n' + httpDate + '\n' + '/' + bucket + uri;

    aws.debug_log(r, 'AWS v2 Auth Signing String: [' + stringToSign + ']');

    const s3signature = hmac.update(stringToSign).digest('base64');

    return `AWS ${credentials.accessKeyId}:${s3signature}`;
}

/**
 * Processes the directory listing output as returned from S3. If
 * FOUR_O_FOUR_ON_EMPTY_BUCKET is enabled, this function will corrupt the
 * XML output by inserting the string 'junk' into the output thereby causing
 * nginx to return a 404 for empty directory listings.
 *
 * If anyone finds a better way to do this, please submit a PR.
 *
 * @param r {Request} HTTP request object (not used, but required for NGINX configuration)
 * @param data chunked data buffer
 * @param flags contains field that indicates that a chunk is last
 */
function filterListResponse(r, data, flags) {
    if (FOUR_O_FOUR_ON_EMPTY_BUCKET) {
        let indexIsEmpty = aws.parseBoolean(r.variables.indexIsEmpty);

        if (indexIsEmpty && data.indexOf('<Contents') >= 0) {
            r.variables.indexIsEmpty = false;
            indexIsEmpty = false;
        }

        if (indexIsEmpty && data.indexOf('<CommonPrefixes') >= 0) {
            r.variables.indexIsEmpty = false;
            indexIsEmpty = false;
        }

        if (flags.last && indexIsEmpty) {
            r.sendBuffer('junk', flags);
        } else {
            r.sendBuffer(data, flags);
        }
    } else {
        r.sendBuffer(data, flags);
    }
}

/**
 * Create HTTP Authorization header for authenticating with an AWS compatible
 * v4 API.
 *
 * @param r {Request} HTTP request object
 * @param timestamp {Date} timestamp associated with request (must fall within a skew)
 * @param bucket {string} S3 bucket associated with request
 * @param region {string} API region associated with request
 * @param server {string}
 * @param credentials {object} Credential object with AWS credentials in it (AccessKeyId, SecretAccessKey, SessionToken)
 * @returns {string} HTTP Authorization header value
 */
function signatureV4(r, timestamp, bucket, region, server, credentials) {
    const eightDigitDate = aws.eightDigitDate(timestamp);
    const amzDatetime = aws.signedDateTime(timestamp, eightDigitDate);
    const signature = _buildSignatureV4(r, amzDatetime, eightDigitDate, credentials, bucket, region, server);
    const authHeader = 'AWS4-HMAC-SHA256 Credential='
        .concat(credentials.accessKeyId, '/', eightDigitDate, '/', region, '/', SERVICE, '/aws4_request,',
            'SignedHeaders=', aws.signedHeaders(credentials.sessionToken), ',Signature=', signature);

    aws.debug_log(r, 'AWS v4 Auth header: [' + authHeader + ']');

    return authHeader;
}

/**
 * Creates a signature for use authenticating against an AWS compatible API.
 *
 * @see {@link https://docs.aws.amazon.com/general/latest/gr/signature-version-4.html | AWS V4 Signing Process}
 * @param r {Request} HTTP request object
 * @param amzDatetime {string} ISO8601 timestamp string to sign request with
 * @param eightDigitDate {string} date in the form of 'YYYYMMDD'
 * @param bucket {string} S3 bucket associated with request
 * @param region {string} API region associated with request
 * @returns {string} hex encoded hash of signature HMAC value
 * @private
 */
function _buildSignatureV4(r, amzDatetime, eightDigitDate, creds, bucket, region, server) {
    let host = server;
    if (S3_STYLE === 'virtual' || S3_STYLE === 'default' || S3_STYLE === undefined) {
        host = bucket + '.' + host;
    }
    const method = r.method;
    const baseUri = s3BaseUri(r);
    const queryParams = _s3DirQueryParams(r.variables.uri_path, method);
    let uri;
    if (queryParams.length > 0) {
        if (baseUri.length > 0) {
            uri = baseUri;
        } else {
            uri = '/';
        }
    } else {
        uri = s3uri(r);
    }

    const canonicalRequest = aws.buildCanonicalRequest(method, uri, queryParams, host, amzDatetime, creds.sessionToken);

    aws.debug_log(r, 'AWS v4 Auth Canonical Request: [' + canonicalRequest + ']');

    const canonicalRequestHash = mod_hmac.createHash('sha256')
        .update(canonicalRequest)
        .digest('hex');

    aws.debug_log(r, 'AWS v4 Auth Canonical Request Hash: [' + canonicalRequestHash + ']');

    const stringToSign = aws.buildStringToSign(amzDatetime, eightDigitDate, region, SERVICE, canonicalRequestHash);

    aws.debug_log(r, 'AWS v4 Auth Signing String: [' + stringToSign + ']');

    let kSigningHash;

    /* If we have a keyval zone and key defined for caching the signing key hash,
     * then signing key caching will be enabled. By caching signing keys we can
     * accelerate the signing process because we will have four less HMAC
     * operations that have to be performed per incoming request. The signing
     * key expires every day, so our cache key can persist for 24 hours safely.
     */
    if ("variables" in r && r.variables.cache_signing_key_enabled == 1) {
        // cached value is in the format: [eightDigitDate]:[signingKeyHash]
        const cached = "signing_key_hash" in r.variables ? r.variables.signing_key_hash : "";
        const fields = aws.splitCachedValues(cached);
        const cachedEightDigitDate = fields[0];
        const cacheIsValid = fields.length === 2 && eightDigitDate === cachedEightDigitDate;

        // If true, use cached value
        if (cacheIsValid) {
            aws.debug_log(r, 'AWS v4 Using cached Signing Key Hash');
            /* We are forced to JSON encode the string returned from the HMAC
             * operation because it is in a very specific format that include
             * binary data and in order to preserve that data when persisting
             * we encode it as JSON. By doing so we can gracefully decode it
             * when reading from the cache. */
            kSigningHash = Buffer.from(JSON.parse(fields[1]));
        // Otherwise, generate a new signing key hash and store it in the cache
        } else {
            kSigningHash = aws.buildSigningKeyHash(creds.secretAccessKey, eightDigitDate, SERVICE, region);
            aws.debug_log(r, 'Writing key: ' + eightDigitDate + ':' + kSigningHash.toString('hex'));
            r.variables.signing_key_hash = eightDigitDate + ':' + JSON.stringify(kSigningHash);
        }
    // Otherwise, don't use caching at all (like when we are using NGINX OSS)
    } else {
        kSigningHash = aws.buildSigningKeyHash(creds.secretAccessKey, eightDigitDate, SERVICE, region);
    }

    aws.debug_log(r, 'AWS v4 Signing Key Hash: [' + kSigningHash.toString('hex') + ']');

    const signature = mod_hmac.createHmac('sha256', kSigningHash)
        .update(stringToSign).digest('hex');

    aws.debug_log(r, 'AWS v4 Authorization Header: [' + signature + ']');

    return signature;
}


/**
 * Adds additional encoding to a URI component
 *
 * @param string {string} string to encode
 * @returns {string} an encoded string
 * @private
 */
function _encodeURIComponent(string) {
    return encodeURIComponent(string)
        .replace(/[!*'()]/g, (c) =>
            `%${c.charCodeAt(0).toString(16).toUpperCase()}`);
}

/**
 * Escapes the path portion of a URI without escaping the path separator
 * characters (/).
 *
 * @param uri {string} unescaped URI
 * @returns {string} URI with each path component separately escaped
 * @private
 */
function _escapeURIPath(uri) {
    // Check to see if the URI path was already encoded. If so, we decode it.
    let decodedUri = (uri.indexOf('%') >= 0) ? decodeURIComponent(uri) : uri;
    let components = [];

    decodedUri.split('/').forEach(function (item, i) {
        components[i] = _encodeURIComponent(item);
    });

    return components.join('/');
}

/**
 * Determines if a given path is a directory based on whether or not the last
 * character in the path is a forward slash (/).
 *
 * @param path {string} path to parse
 * @returns {boolean} true if path is a directory
 * @private
 */
function _isDirectory(path) {
    if (path === undefined) {
        return false;
    }
    const len = path.length;

    if (len < 1) {
        return false;
    }

    return path.charAt(len - 1) === '/';
}

/**
 * Parses a string delimited by semicolons into an array of values
 * @param string {string|null} value representing a array of strings
 * @returns {Array} a list of values
 * @private
 */
function _parseArray(string) {
    if (string == null || !string || string === ';') {
        return [];
    }

    // Exclude trailing delimiter
    if (string.endsWith(';')) {
        return string.substr(0, string.length - 1).split(';');
    }

    return string.split(';')
}

/**
 * Checks to see if the given environment variable is present. If not, an error
 * is thrown.
 * @param envVarName {string} environment variable to check for
 * @private
 */
function _require_env_var(envVarName) {
    const isSet = envVarName in process.env;

    if (!isSet) {
        throw('Required environment variable ' + envVarName + ' is missing');
    }
}

export default {
    s3auth,
    s3uri,
    trailslashControl,
    redirectToS3,
    editHeaders,
    filterListResponse,
    // These functions do not need to be exposed, but they are exposed so that
    // unit tests can run against them.
    _encodeURIComponent,
    _buildSignatureV4,
    _escapeURIPath,
    _parseArray,
    _isHeaderToBeStripped
};
