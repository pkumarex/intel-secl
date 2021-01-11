/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package kbs

// ---

// swagger:operation POST /tpm-identity-certificates TpmIdentityCertificates ImportTpmIdentityCertificate
// ---
//
// description: |
//   </b>Imports a privacy-ca certificate.</b>
//   <pre>
//   This method registers a HVS privacy-ca public key certificate to the service. During the
//   SAML transfer key API call, a SAML report containing a host TPM AIK certificate is provided.
//   It is verified that a HVS privacy-ca certificate registered with this service has signed this
//   AIK. The binding key certificate is retrieved from the SAML report and it verifies that a
//   HVS privacy-ca certificate has signed this cert as well. The certificate object model includes
//   an ID, base64 encoded certificate and a revoked status.
//   </pre>
//
// x-permissions: tpm-identity-certificates:create
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
//     description: Successfully imported the tpm-identity certificate.
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
// x-sample-call-endpoint: https://kbs.com:9443/kbs/v1/tpm-identity-certificates
// x-sample-call-input: |
//     -----BEGIN CERTIFICATE-----
//     MIIDMjCCAhqgAwIBAgIGAWfO03T4MA0GCSqGSIb3DQEBCwUAMBsxGTAXBgNVBAMTEG10d2lsc29u
//     LXBjYS1haWswHhcNMTgxMjIxMDMzMzQzWhcNMjgxMjIwMDMzMzQzWjAbMRkwFwYDVQQDExBtdHdp
//     bHNvbi1wY2EtYWlrMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAh1ci0WLpy+8hZeMt
//     Gt6pH1tQYKS4IsKthZYcoJAoPKk3OZZr0egw12eOEJY2zV6l5OXq98NQ3GevvuDy/9GVcNjhIO/h
//     Yn0LkedL3QF34TZrpVFb5seap+ppcgHUflVVqmcKMl8LpwlXxxkN0ABasajjKmBAQ6CUgL6KXVCE
//     xUxyDOo46iz9muoJo3sZ71YXHLRUyPp4t1YBx8xwOA2hKE+uB1hhcABNTLu0CTdt5Wbh+Xe+MQhg
//     HIhmJaTeBq5HGQa7iTfAmdWwwGW9OOHHXP33ppahQ5KaZ6301hz50Xtdobvlvwo0xGO3UJSL9zAB
//     GV+Y27j1FRtD0rYPZEFTAwIDAQABo3wwejAdBgNVHQ4EFgQUL9YUt/Yv5BXKsYiJJK7CzXdEuZsw
//     DwYDVR0TAQH/BAUwAwEB/zBIBgNVHSMEQTA/gBQv1hS39i/kFcqxiIkkrsLNd0S5m6EfpB0wGzEZ
//     MBcGA1UEAxMQbXR3aWxzb24tcGNhLWFpa4IGAWfO03T4MA0GCSqGSIb3DQEBCwUAA4IBAQAUdD1c
//     3KHGI7KLZ2YZ//PliNSzNyuM6BCRN7ZCmlwDhwbPKkxVEeuPEQ+rT3eVE87Tvzx/Bwk18kI8ErB+
//     6oQRO6KiZFnGOedHzaKT8GgQjmRSdszj2lRq6+1UCXIxeT8HVUAFUVgOa4bMndRZmlkwuhoSblsf
//     kEDAojfh8EJa1/i52tkJR+uIy/7/D3wY2UEzYxoNquuDKlPWDbp2G48MOMMdhRk3HfDDna66mm3/
//     DLhcRFbzNUIhWvn5Kp5sGGiN/VgQCHdDFvnZH/k0W1a/SO5gGTL/ttVjWFjEdDaKs34EPA4ySlW4
//     t4WHBaD1mPVF39J7Y6QBlbvGo6JLKVFO
//     -----END CERTIFICATE-----
// x-sample-call-output: |
//    {
//        "id": "cd4f4fc4-73d4-42ac-a0d2-0fe896ec694c",
//        "certificate": "MIIDMjCCAhqgAwIBAgIGAWfO03T4MA0GCSqGSIb3DQEBCwUAMBsxGTAXBgNVBAMTEG10d2lsc29u
//                        LXBjYS1haWswHhcNMTgxMjIxMDMzMzQzWhcNMjgxMjIwMDMzMzQzWjAbMRkwFwYDVQQDExBtdHdp
//                        bHNvbi1wY2EtYWlrMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAh1ci0WLpy+8hZeMt
//                        Gt6pH1tQYKS4IsKthZYcoJAoPKk3OZZr0egw12eOEJY2zV6l5OXq98NQ3GevvuDy/9GVcNjhIO/h
//                        Yn0LkedL3QF34TZrpVFb5seap+ppcgHUflVVqmcKMl8LpwlXxxkN0ABasajjKmBAQ6CUgL6KXVCE
//                        xUxyDOo46iz9muoJo3sZ71YXHLRUyPp4t1YBx8xwOA2hKE+uB1hhcABNTLu0CTdt5Wbh+Xe+MQhg
//                        HIhmJaTeBq5HGQa7iTfAmdWwwGW9OOHHXP33ppahQ5KaZ6301hz50Xtdobvlvwo0xGO3UJSL9zAB
//                        GV+Y27j1FRtD0rYPZEFTAwIDAQABo3wwejAdBgNVHQ4EFgQUL9YUt/Yv5BXKsYiJJK7CzXdEuZsw
//                        DwYDVR0TAQH/BAUwAwEB/zBIBgNVHSMEQTA/gBQv1hS39i/kFcqxiIkkrsLNd0S5m6EfpB0wGzEZ
//                        MBcGA1UEAxMQbXR3aWxzb24tcGNhLWFpa4IGAWfO03T4MA0GCSqGSIb3DQEBCwUAA4IBAQAUdD1c
//                        3KHGI7KLZ2YZ//PliNSzNyuM6BCRN7ZCmlwDhwbPKkxVEeuPEQ+rT3eVE87Tvzx/Bwk18kI8ErB+
//                        6oQRO6KiZFnGOedHzaKT8GgQjmRSdszj2lRq6+1UCXIxeT8HVUAFUVgOa4bMndRZmlkwuhoSblsf
//                        kEDAojfh8EJa1/i52tkJR+uIy/7/D3wY2UEzYxoNquuDKlPWDbp2G48MOMMdhRk3HfDDna66mm3/
//                        DLhcRFbzNUIhWvn5Kp5sGGiN/VgQCHdDFvnZH/k0W1a/SO5gGTL/ttVjWFjEdDaKs34EPA4ySlW4
//                        t4WHBaD1mPVF39J7Y6QBlbvGo6JLKVFO",
//        "subject": "HVS Privacy CA",
//        "issuer": "HVS Privacy CA",
//        "not_before": "2020-07-20T18:39:10Z",
//        "not_after": "2021-07-20T18:39:10Z",
//        "revoked": false
//    }

// ---

// swagger:operation GET /tpm-identity-certificates/{id} TpmIdentityCertificates RetrieveTpmIdentityCertificate
// ---
//
// description: |
//   Retrieves a privacy-ca certificate.
//   Returns - The serialized Certificate Go struct object that was retrieved.
// x-permissions: tpm-identity-certificates:retrieve
// security:
//  - bearerAuth: []
// produces:
// - application/json
// parameters:
// - name: id
//   description: Unique ID of the tpm-identity certificate.
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
//     description: Successfully retrieved the tpm-identity certificate.
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
// x-sample-call-endpoint: https://kbs.com:9443/kbs/v1/tpm-identity-certificates/cd4f4fc4-73d4-42ac-a0d2-0fe896ec694c
// x-sample-call-output: |
//    {
//        "id": "cd4f4fc4-73d4-42ac-a0d2-0fe896ec694c",
//        "certificate": "MIIDMjCCAhqgAwIBAgIGAWfO03T4MA0GCSqGSIb3DQEBCwUAMBsxGTAXBgNVBAMTEG10d2lsc29u
//                        LXBjYS1haWswHhcNMTgxMjIxMDMzMzQzWhcNMjgxMjIwMDMzMzQzWjAbMRkwFwYDVQQDExBtdHdp
//                        bHNvbi1wY2EtYWlrMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAh1ci0WLpy+8hZeMt
//                        Gt6pH1tQYKS4IsKthZYcoJAoPKk3OZZr0egw12eOEJY2zV6l5OXq98NQ3GevvuDy/9GVcNjhIO/h
//                        Yn0LkedL3QF34TZrpVFb5seap+ppcgHUflVVqmcKMl8LpwlXxxkN0ABasajjKmBAQ6CUgL6KXVCE
//                        xUxyDOo46iz9muoJo3sZ71YXHLRUyPp4t1YBx8xwOA2hKE+uB1hhcABNTLu0CTdt5Wbh+Xe+MQhg
//                        HIhmJaTeBq5HGQa7iTfAmdWwwGW9OOHHXP33ppahQ5KaZ6301hz50Xtdobvlvwo0xGO3UJSL9zAB
//                        GV+Y27j1FRtD0rYPZEFTAwIDAQABo3wwejAdBgNVHQ4EFgQUL9YUt/Yv5BXKsYiJJK7CzXdEuZsw
//                        DwYDVR0TAQH/BAUwAwEB/zBIBgNVHSMEQTA/gBQv1hS39i/kFcqxiIkkrsLNd0S5m6EfpB0wGzEZ
//                        MBcGA1UEAxMQbXR3aWxzb24tcGNhLWFpa4IGAWfO03T4MA0GCSqGSIb3DQEBCwUAA4IBAQAUdD1c
//                        3KHGI7KLZ2YZ//PliNSzNyuM6BCRN7ZCmlwDhwbPKkxVEeuPEQ+rT3eVE87Tvzx/Bwk18kI8ErB+
//                        6oQRO6KiZFnGOedHzaKT8GgQjmRSdszj2lRq6+1UCXIxeT8HVUAFUVgOa4bMndRZmlkwuhoSblsf
//                        kEDAojfh8EJa1/i52tkJR+uIy/7/D3wY2UEzYxoNquuDKlPWDbp2G48MOMMdhRk3HfDDna66mm3/
//                        DLhcRFbzNUIhWvn5Kp5sGGiN/VgQCHdDFvnZH/k0W1a/SO5gGTL/ttVjWFjEdDaKs34EPA4ySlW4
//                        t4WHBaD1mPVF39J7Y6QBlbvGo6JLKVFO",
//        "subject": "HVS Privacy CA",
//        "issuer": "HVS Privacy CA",
//        "not_before": "2020-07-20T18:39:10Z",
//        "not_after": "2021-07-20T18:39:10Z",
//        "revoked": false
//    }

// ---

// swagger:operation DELETE /tpm-identity-certificates/{id} TpmIdentityCertificates DeleteTpmIdentityCertificate
// ---
//
// description: |
//   Deletes a privacy-ca certificate.
// x-permissions: tpm-identity-certificates:delete
// security:
//  - bearerAuth: []
// parameters:
// - name: id
//   description: Unique ID of the tpm-identity certificate.
//   in: path
//   required: true
//   type: string
//   format: uuid
// responses:
//   '204':
//     description: Successfully deleted the tpm-identity certificate.
//   '404':
//     description: Certificate record not found
//   '500':
//     description: Internal server error
// x-sample-call-endpoint: https://kbs.com:9443/kbs/v1/tpm-identity-certificates/cd4f4fc4-73d4-42ac-a0d2-0fe896ec694c

// ---

// swagger:operation GET /tpm-identity-certificates TpmIdentityCertificates SearchTpmIdentityCertificates
// ---
//
// description: |
//   Searches for privacy-ca certificates.
//   Returns - The collection of serialized Certificate Go struct objects.
// x-permissions: tpm-identity-certificates:search
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
//     description: Successfully retrieved the tpm-identity certificates.
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
// x-sample-call-endpoint: https://kbs.com:9443/kbs/v1/tpm-identity-certificates
// x-sample-call-output: |
//    [
//        {
//            "id": "cd4f4fc4-73d4-42ac-a0d2-0fe896ec694c",
//            "certificate": "MIIDMjCCAhqgAwIBAgIGAWfO03T4MA0GCSqGSIb3DQEBCwUAMBsxGTAXBgNVBAMTEG10d2lsc29u
//                            LXBjYS1haWswHhcNMTgxMjIxMDMzMzQzWhcNMjgxMjIwMDMzMzQzWjAbMRkwFwYDVQQDExBtdHdp
//                            bHNvbi1wY2EtYWlrMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAh1ci0WLpy+8hZeMt
//                            Gt6pH1tQYKS4IsKthZYcoJAoPKk3OZZr0egw12eOEJY2zV6l5OXq98NQ3GevvuDy/9GVcNjhIO/h
//                            Yn0LkedL3QF34TZrpVFb5seap+ppcgHUflVVqmcKMl8LpwlXxxkN0ABasajjKmBAQ6CUgL6KXVCE
//                            xUxyDOo46iz9muoJo3sZ71YXHLRUyPp4t1YBx8xwOA2hKE+uB1hhcABNTLu0CTdt5Wbh+Xe+MQhg
//                            HIhmJaTeBq5HGQa7iTfAmdWwwGW9OOHHXP33ppahQ5KaZ6301hz50Xtdobvlvwo0xGO3UJSL9zAB
//                            GV+Y27j1FRtD0rYPZEFTAwIDAQABo3wwejAdBgNVHQ4EFgQUL9YUt/Yv5BXKsYiJJK7CzXdEuZsw
//                            DwYDVR0TAQH/BAUwAwEB/zBIBgNVHSMEQTA/gBQv1hS39i/kFcqxiIkkrsLNd0S5m6EfpB0wGzEZ
//                            MBcGA1UEAxMQbXR3aWxzb24tcGNhLWFpa4IGAWfO03T4MA0GCSqGSIb3DQEBCwUAA4IBAQAUdD1c
//                            3KHGI7KLZ2YZ//PliNSzNyuM6BCRN7ZCmlwDhwbPKkxVEeuPEQ+rT3eVE87Tvzx/Bwk18kI8ErB+
//                            6oQRO6KiZFnGOedHzaKT8GgQjmRSdszj2lRq6+1UCXIxeT8HVUAFUVgOa4bMndRZmlkwuhoSblsf
//                            kEDAojfh8EJa1/i52tkJR+uIy/7/D3wY2UEzYxoNquuDKlPWDbp2G48MOMMdhRk3HfDDna66mm3/
//                            DLhcRFbzNUIhWvn5Kp5sGGiN/VgQCHdDFvnZH/k0W1a/SO5gGTL/ttVjWFjEdDaKs34EPA4ySlW4
//                            t4WHBaD1mPVF39J7Y6QBlbvGo6JLKVFO",
//            "subject": "HVS Privacy CA",
//            "issuer": "HVS Privacy CA",
//            "not_before": "2020-07-20T18:39:10Z",
//            "not_after": "2021-07-20T18:39:10Z",
//            "revoked": false
//        }
//    ]
