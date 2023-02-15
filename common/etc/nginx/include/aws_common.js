
/*
 *  Copyright 2023 F5, Inc.
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

/**
 * Constant checksum for an empty HTTP body.
 * @type {string}
 */
const EMPTY_PAYLOAD_HASH = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';

/**
 * Constant defining the headers being signed.
 * @type {string}
 */
const DEFAULT_SIGNED_HEADERS = 'host;x-amz-content-sha256;x-amz-date';

/**
 * Creates a string containing the headers that need to be signed as part of v4
 * signature authentication.
 *
 * @param sessionToken {string|undefined} AWS session token if present
 * @returns {string} semicolon delimited string of the headers needed for signing
 */
function signedHeaders(sessionToken) {
    let headers = DEFAULT_SIGNED_HEADERS;
    if (sessionToken) {
        headers += ';x-amz-security-token';
    }
    return headers;
}

/**
 * Creates a canonical request that will later be signed
 *
 * @see {@link https://docs.aws.amazon.com/general/latest/gr/sigv4-create-canonical-request.html | Creating a Canonical Request}
 * @param method {string} HTTP method
 * @param uri {string} URI associated with request
 * @param queryParams {string} query parameters associated with request
 * @param host {string} HTTP Host header value
 * @param amzDatetime {string} ISO8601 timestamp string to sign request with
 * @returns {string} string with concatenated request parameters
 * @private
 */
function buildCanonicalRequest(method, uri, queryParams, host, amzDatetime, sessionToken) {
    let canonicalHeaders = 'host:' + host + '\n' +
        'x-amz-content-sha256:' + EMPTY_PAYLOAD_HASH + '\n' +
        'x-amz-date:' + amzDatetime + '\n';

    if (sessionToken) {
        canonicalHeaders += 'x-amz-security-token:' + sessionToken + '\n'
    }

    let canonicalRequest = method + '\n';
    canonicalRequest += uri + '\n';
    if (queryParams) {
        canonicalRequest += queryParams + '\n';
    }
    canonicalRequest += canonicalHeaders + '\n';
    canonicalRequest += signedHeaders(sessionToken) + '\n';
    canonicalRequest += EMPTY_PAYLOAD_HASH;

    return canonicalRequest;
}

/**
 * Splits the cached values into an array with two elements or returns an
 * empty array if the input string is invalid. The first element contains
 * the eight digit date string and the second element contains a JSON string
 * of the kSigningHash.
 *
 * @param cached input string to parse
 * @returns {string[]|*[]} array containing eight digit date and kSigningHash or empty
 * @private
 */
function splitCachedValues(cached) {
    const matchedPos = cached.indexOf(':', 0);
    // Do a sanity check on the position returned, if it isn't sane, return
    // an empty array and let the caller logic process it.
    if (matchedPos < 0 || matchedPos + 1 > cached.length) {
        return []
    }

    const eightDigitDate = cached.substring(0, matchedPos);
    const kSigningHash = cached.substring(matchedPos + 1);

    return [eightDigitDate, kSigningHash]
}

/**
 * Creates a signing key HMAC. This value is used to sign the request made to
 * the API.
 *
 * @param kSecret {string} secret access key
 * @param eightDigitDate {string} date in the form of 'YYYYMMDD'
 * @param service {string} name of service that request is for e.g. s3, iam, etc
 * @param region {string} region associated with server API
 * @returns {ArrayBuffer} signing HMAC
 * @private
 */
function buildSigningKeyHash(kSecret, eightDigitDate, service, region) {
    const kDate = mod_hmac.createHmac('sha256', 'AWS4'.concat(kSecret))
        .update(eightDigitDate).digest();
    const kRegion = mod_hmac.createHmac('sha256', kDate)
        .update(region).digest();
    const kService = mod_hmac.createHmac('sha256', kRegion)
        .update(service).digest();
    const kSigning = mod_hmac.createHmac('sha256', kService)
        .update('aws4_request').digest();

    return kSigning;
}

export default {
    buildCanonicalRequest,
    buildSigningKeyHash,
    signedHeaders,
    splitCachedValues
}
