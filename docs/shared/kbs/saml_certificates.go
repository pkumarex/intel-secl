/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package kbs

import "github.com/intel-secl/intel-secl/v3/pkg/model/kbs"

type Certificates []kbs.Certificate

// Certificate request/response payload
// swagger:parameters Certificate
type Certificate struct {
	// in:body
	Body kbs.Certificate
}

// CertificateCollection response payload
// swagger:parameters CertificateCollection
type CertificateCollection struct {
	// in:body
	Body Certificates
}

// ---

// swagger:operation POST /saml-certificates SamlCertificates ImportSamlCertificate
// ---
//
// description: |
//   </b>Imports a saml certificate.</b>
//   <pre>
//   This method registers a SAML public key certificate to this service. During the SAML transfer
//   key API call, a SAML report containing the same SAML certificate is provided and the
//   certificate is compared and verified against the SAML certificates registered with this service.
//   The certificate object model includes an ID, base64 encoded certificate and a revoked status.
//   </pre>
//
// x-permissions: saml-certificates:create
// security:
//  - bearerAuth: []
// produces:
// - application/json
// consumes:
// - application/x-pem-file
// parameters:
// - name: Content-Type
//   description: Content-Type header
//   in: header
//   type: string
//   required: true
//   enum:
//     - application/x-pem-file
// - name: Accept
//   description: Accept header
//   in: header
//   type: string
//   required: true
//   enum:
//     - application/json
// responses:
//   '201':
//     description: Successfully imported the saml certificate.
//     content:
//       application/json
//     schema:
//       $ref: "#/definitions/Certificate"
//   '400':
//     description: Invalid request body provided
//   '415':
//     description: Invalid Accept Header in Request
//   '500':
//     description: Internal server error
//
// x-sample-call-endpoint: https://kbs.com:9443/kbs/v1/saml-certificates
// x-sample-call-input: |
//    -----BEGIN CERTIFICATE-----
//    MIIDIjCCAgqgAwIBAgIIBrxF7PYTjakwDQYJKoZIhvcNAQELBQAwUTELMAkGA1UEBhMCVVMxHDAa
//    BgNVBAoTE1RydXN0ZWQgRGF0YSBDZW50ZXIxEjAQBgNVBAsTCU10IFdpbHNvbjEQMA4GA1UEAxMH
//    Q049dGVzdDAeFw0xODEyMjcwMzI3MzZaFw0xODEyMjcwNDI3MzZaMFExCzAJBgNVBAYTAlVTMRww
//    GgYDVQQKExNUcnVzdGVkIERhdGEgQ2VudGVyMRIwEAYDVQQLEwlNdCBXaWxzb24xEDAOBgNVBAMT
//    B0NOPXRlc3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCohoz8Ptxnfqv+iZMApxGz
//    ra5viot1dbYLL+OVY5/1+S1yEFXNUPmELO6gGhmRPO9LQgCgIRiSDSWTjiOXcoVppEQfgCQupSpr
//    eHeXyc37Ee5dAk7rwansVjAFJtnrPzOeuVpRAxvI6FWd6qTKRhItaaGITx8n9MJXdL5Gd3qPeBXP
//    Uj/U2aS9ViBajDPVxcAEeyWZsjxw+FdEtylCLR/nRYB70xafWuU7/iZWe5uPqbkldOD6xMK2hYhC
//    wit5y6F79uDB+2OULOA5cnQPh+enWbqNiVCiW1sV+fZWcjo24q9duG6Kv7B0UawtF2TYoXKJkzwr
//    pYRTVBpnZoH9jrzvAgMBAAEwDQYJKoZIhvcNAQELBQADggEBADEC64z3kyfOMMOkAO3OcQqjhwmH
//    6UMslSjakNi2SmXMWeF/JUJmasawaKy0eQ9iZrgDIPw4ndvd0CaY3bf9e0eIijoYsrD2/oOw4f9U
//    BZsbKE44s9QX7Byi5D1xtCxuKdRWFK+487GHuNAYpR/7Cgff2DVDro1q2WZLwgJs9X0TMqXzSJV3
//    //HsWVIKRzXR14dJqrXO8JbQzWy5z+j5bHnSsTL2WmJY+a5xPdlPitbkKQDlPeHWKMA3IwsjHtNM
//    v39A87oxcrc7rx6CycfSFDidz8a5OVH5Hkm4XquX6K2LDLcbesAkdId9Yge92zO0cHTZI2rD/ztF
//    Yz78/Zo9py8=
//    -----END CERTIFICATE-----
// x-sample-call-output: |
//    {
//        "id": "9ea0c8b5-590f-481d-a5de-46edfbfbf8cc",
//        "certificate": "MIIDIjCCAgqgAwIBAgIIBrxF7PYTjakwDQYJKoZIhvcNAQELBQAwUTELMAkGA1UEBhMCVVMxHDAa
//                        BgNVBAoTE1RydXN0ZWQgRGF0YSBDZW50ZXIxEjAQBgNVBAsTCU10IFdpbHNvbjEQMA4GA1UEAxMH
//                        Q049dGVzdDAeFw0xODEyMjcwMzI3MzZaFw0xODEyMjcwNDI3MzZaMFExCzAJBgNVBAYTAlVTMRww
//                        GgYDVQQKExNUcnVzdGVkIERhdGEgQ2VudGVyMRIwEAYDVQQLEwlNdCBXaWxzb24xEDAOBgNVBAMT
//                        B0NOPXRlc3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCohoz8Ptxnfqv+iZMApxGz
//                        ra5viot1dbYLL+OVY5/1+S1yEFXNUPmELO6gGhmRPO9LQgCgIRiSDSWTjiOXcoVppEQfgCQupSpr
//                        eHeXyc37Ee5dAk7rwansVjAFJtnrPzOeuVpRAxvI6FWd6qTKRhItaaGITx8n9MJXdL5Gd3qPeBXP
//                        Uj/U2aS9ViBajDPVxcAEeyWZsjxw+FdEtylCLR/nRYB70xafWuU7/iZWe5uPqbkldOD6xMK2hYhC
//                        wit5y6F79uDB+2OULOA5cnQPh+enWbqNiVCiW1sV+fZWcjo24q9duG6Kv7B0UawtF2TYoXKJkzwr
//                        pYRTVBpnZoH9jrzvAgMBAAEwDQYJKoZIhvcNAQELBQADggEBADEC64z3kyfOMMOkAO3OcQqjhwmH
//                        6UMslSjakNi2SmXMWeF/JUJmasawaKy0eQ9iZrgDIPw4ndvd0CaY3bf9e0eIijoYsrD2/oOw4f9U
//                        BZsbKE44s9QX7Byi5D1xtCxuKdRWFK+487GHuNAYpR/7Cgff2DVDro1q2WZLwgJs9X0TMqXzSJV3
//                        //HsWVIKRzXR14dJqrXO8JbQzWy5z+j5bHnSsTL2WmJY+a5xPdlPitbkKQDlPeHWKMA3IwsjHtNM
//                        v39A87oxcrc7rx6CycfSFDidz8a5OVH5Hkm4XquX6K2LDLcbesAkdId9Yge92zO0cHTZI2rD/ztF
//                        Yz78/Zo9py8=",
//        "subject": "mtwilson-saml",
//        "issuer": "CMS Signing CA",
//        "not_before": "2020-07-20T13:55:00Z",
//        "not_after": "2021-07-20T13:55:00Z",
//        "revoked": false
//    }

// ---

// swagger:operation GET /saml-certificates/{id} SamlCertificates RetrieveSamlCertificate
// ---
//
// description: |
//   Retrieves a saml certificate.
//   Returns - The serialized Certificate Go struct object that was retrieved.
// x-permissions: saml-certificates:retrieve
// security:
//  - bearerAuth: []
// produces:
// - application/json
// parameters:
// - name: id
//   description: Unique ID of the saml certificate.
//   in: path
//   required: true
//   type: string
//   format: uuid
// - name: Accept
//   description: Accept header
//   in: header
//   type: string
//   required: true
//   enum:
//     - application/json
// responses:
//   '200':
//     description: Successfully retrieved the saml certificate.
//     content:
//       application/json
//     schema:
//       $ref: "#/definitions/Certificate"
//   '404':
//     description: Certificate record not found
//   '415':
//     description: Invalid Accept Header in Request
//   '500':
//     description: Internal server error
//
// x-sample-call-endpoint: https://kbs.com:9443/kbs/v1/saml-certificates/9ea0c8b5-590f-481d-a5de-46edfbfbf8cc
// x-sample-call-output: |
//    {
//        "id": "9ea0c8b5-590f-481d-a5de-46edfbfbf8cc",
//        "certificate": "MIIDIjCCAgqgAwIBAgIIBrxF7PYTjakwDQYJKoZIhvcNAQELBQAwUTELMAkGA1UEBhMCVVMxHDAa
//                        BgNVBAoTE1RydXN0ZWQgRGF0YSBDZW50ZXIxEjAQBgNVBAsTCU10IFdpbHNvbjEQMA4GA1UEAxMH
//                        Q049dGVzdDAeFw0xODEyMjcwMzI3MzZaFw0xODEyMjcwNDI3MzZaMFExCzAJBgNVBAYTAlVTMRww
//                        GgYDVQQKExNUcnVzdGVkIERhdGEgQ2VudGVyMRIwEAYDVQQLEwlNdCBXaWxzb24xEDAOBgNVBAMT
//                        B0NOPXRlc3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCohoz8Ptxnfqv+iZMApxGz
//                        ra5viot1dbYLL+OVY5/1+S1yEFXNUPmELO6gGhmRPO9LQgCgIRiSDSWTjiOXcoVppEQfgCQupSpr
//                        eHeXyc37Ee5dAk7rwansVjAFJtnrPzOeuVpRAxvI6FWd6qTKRhItaaGITx8n9MJXdL5Gd3qPeBXP
//                        Uj/U2aS9ViBajDPVxcAEeyWZsjxw+FdEtylCLR/nRYB70xafWuU7/iZWe5uPqbkldOD6xMK2hYhC
//                        wit5y6F79uDB+2OULOA5cnQPh+enWbqNiVCiW1sV+fZWcjo24q9duG6Kv7B0UawtF2TYoXKJkzwr
//                        pYRTVBpnZoH9jrzvAgMBAAEwDQYJKoZIhvcNAQELBQADggEBADEC64z3kyfOMMOkAO3OcQqjhwmH
//                        6UMslSjakNi2SmXMWeF/JUJmasawaKy0eQ9iZrgDIPw4ndvd0CaY3bf9e0eIijoYsrD2/oOw4f9U
//                        BZsbKE44s9QX7Byi5D1xtCxuKdRWFK+487GHuNAYpR/7Cgff2DVDro1q2WZLwgJs9X0TMqXzSJV3
//                        //HsWVIKRzXR14dJqrXO8JbQzWy5z+j5bHnSsTL2WmJY+a5xPdlPitbkKQDlPeHWKMA3IwsjHtNM
//                        v39A87oxcrc7rx6CycfSFDidz8a5OVH5Hkm4XquX6K2LDLcbesAkdId9Yge92zO0cHTZI2rD/ztF
//                        Yz78/Zo9py8=",
//        "subject": "mtwilson-saml",
//        "issuer": "CMS Signing CA",
//        "not_before": "2020-07-20T13:55:00Z",
//        "not_after": "2021-07-20T13:55:00Z",
//        "revoked": false
//    }

// ---

// swagger:operation DELETE /saml-certificates/{id} SamlCertificates DeleteSamlCertificate
// ---
//
// description: |
//   Deletes a saml certificate.
// x-permissions: saml-certificates:delete
// security:
//  - bearerAuth: []
// parameters:
// - name: id
//   description: Unique ID of the saml certificate.
//   in: path
//   required: true
//   type: string
//   format: uuid
// responses:
//   '204':
//     description: Successfully deleted the saml certificate.
//   '404':
//     description: Certificate record not found
//   '500':
//     description: Internal server error
// x-sample-call-endpoint: https://kbs.com:9443/kbs/v1/saml-certificates/9ea0c8b5-590f-481d-a5de-46edfbfbf8cc

// ---

// swagger:operation GET /saml-certificates SamlCertificates SearchSamlCertificates
// ---
//
// description: |
//   Searches for saml certificates.
//   Returns - The collection of serialized Certificate Go struct objects.
// x-permissions: saml-certificates:search
// security:
//  - bearerAuth: []
// produces:
//  - application/json
// parameters:
// - name: Accept
//   description: Accept header
//   in: header
//   type: string
//   required: true
//   enum:
//     - application/json
// responses:
//   '200':
//     description: Successfully retrieved the saml certificates.
//     content:
//       application/json
//     schema:
//       $ref: "#/definitions/Certificates"
//   '400':
//     description: Invalid values for request params
//   '415':
//     description: Invalid Accept Header in Request
//   '500':
//     description: Internal server error
//
// x-sample-call-endpoint: https://kbs.com:9443/kbs/v1/saml-certificates
// x-sample-call-output: |
//    [
//        {
//            "id": "9ea0c8b5-590f-481d-a5de-46edfbfbf8cc",
//            "certificate": "MIIDIjCCAgqgAwIBAgIIBrxF7PYTjakwDQYJKoZIhvcNAQELBQAwUTELMAkGA1UEBhMCVVMxHDAa
//                            BgNVBAoTE1RydXN0ZWQgRGF0YSBDZW50ZXIxEjAQBgNVBAsTCU10IFdpbHNvbjEQMA4GA1UEAxMH
//                            Q049dGVzdDAeFw0xODEyMjcwMzI3MzZaFw0xODEyMjcwNDI3MzZaMFExCzAJBgNVBAYTAlVTMRww
//                            GgYDVQQKExNUcnVzdGVkIERhdGEgQ2VudGVyMRIwEAYDVQQLEwlNdCBXaWxzb24xEDAOBgNVBAMT
//                            B0NOPXRlc3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCohoz8Ptxnfqv+iZMApxGz
//                            ra5viot1dbYLL+OVY5/1+S1yEFXNUPmELO6gGhmRPO9LQgCgIRiSDSWTjiOXcoVppEQfgCQupSpr
//                            eHeXyc37Ee5dAk7rwansVjAFJtnrPzOeuVpRAxvI6FWd6qTKRhItaaGITx8n9MJXdL5Gd3qPeBXP
//                            Uj/U2aS9ViBajDPVxcAEeyWZsjxw+FdEtylCLR/nRYB70xafWuU7/iZWe5uPqbkldOD6xMK2hYhC
//                            wit5y6F79uDB+2OULOA5cnQPh+enWbqNiVCiW1sV+fZWcjo24q9duG6Kv7B0UawtF2TYoXKJkzwr
//                            pYRTVBpnZoH9jrzvAgMBAAEwDQYJKoZIhvcNAQELBQADggEBADEC64z3kyfOMMOkAO3OcQqjhwmH
//                            6UMslSjakNi2SmXMWeF/JUJmasawaKy0eQ9iZrgDIPw4ndvd0CaY3bf9e0eIijoYsrD2/oOw4f9U
//                            BZsbKE44s9QX7Byi5D1xtCxuKdRWFK+487GHuNAYpR/7Cgff2DVDro1q2WZLwgJs9X0TMqXzSJV3
//                            //HsWVIKRzXR14dJqrXO8JbQzWy5z+j5bHnSsTL2WmJY+a5xPdlPitbkKQDlPeHWKMA3IwsjHtNM
//                            v39A87oxcrc7rx6CycfSFDidz8a5OVH5Hkm4XquX6K2LDLcbesAkdId9Yge92zO0cHTZI2rD/ztF
//                            Yz78/Zo9py8=",
//            "subject": "mtwilson-saml",
//            "issuer": "CMS Signing CA",
//            "not_before": "2020-07-20T13:55:00Z",
//            "not_after": "2021-07-20T13:55:00Z",
//            "revoked": false
//        }
//    ]
