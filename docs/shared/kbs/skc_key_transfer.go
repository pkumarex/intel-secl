/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package kbs

import "github.com/intel-secl/intel-secl/v3/pkg/model/kbs"

// KeyTransfer response payload
// swagger:parameters KeyTransferResponse
type KeyTransferResponse struct {
	// in:body
	Body kbs.KeyTransferResponse
}

// ---

// swagger:operation GET /keys/{id}/dhsm2-transfer Keys SKCTransferKey
// ---
//
// description: |
//   Transfers a key to the SKC-Library. TLS-Mutual authentication happens between KBS and SKC-Library, hence skc-client certificate and root-ca certificate needs to be provided in the request.
//
//   Returns - The serialized KeyTransferResponse Go struct object that was retrieved.
// security:
//  - bearerAuth: []
// produces:
// - application/json
// parameters:
// - name: id
//   description: Unique ID of the key.
//   in: path
//   required: true
//   type: string
//   format: uuid
// - name: Accept-Challenge
//   description: SKC Challenge Type
//   in: header
//   type: string
//   required: true
//   enum:
//     - SGX
//     - SW
// - name: Session-Id
//   description: Mapping of challenge-type and session-id. KBS returns base64-encoded session-id in the form of challenge. Provide decoded session-id value in header, e.g. SGX:19c3f009-39c9-4734-a535-edb42c76dfa8.
//   in: header
//   type: string
//   required: true
// - name: Accept
//   description: Accept header
//   in: header
//   type: string
//   required: true
//   enum:
//     - application/json
// responses:
//   '200':
//     description: Successfully transferred the key.
//     headers:
//       Session-Id:
//         type: string
//         description: Mapping of challenge-type and session-id.
//     content:
//       application/json
//     schema:
//       $ref: "#/definitions/KeyTransferResponse"
//   '400':
//     description: Invalid transfer request
//   '404':
//     description: Key record not found
//   '401':
//     description: Unauthorized request
//   '500':
//     description: Internal server error
//
// x-sample-call-endpoint: https://kbs.com:9443/kbs/v1/keys/fc0cc779-22b6-4741-b0d9-e2e69635ad1e/dhsm2-transfer
// x-sample-call-output: |
//  {
//      "data": {
//              "id": "a8db4abf-f404-44d3-91c4-0842b90527f3",
//              "payload": "DAAAABAAAADSBAAA/yMWqZhF/VrrVD5fqQLpYh55sqze8U7KkAaC4zwxwOptlC6smFqwr6mq3k18ItpIz8II9KsBmIVRwO5C2X1Ay4XTdLRDNmR8u2ftCnqkOekHAcs/Fa+XlhLbGHl3vzqle/x+AAeJWk1CtTs2J5+293mLhTCqRi4HOfCo4YpBQCL+ga7yJpZGTwk4yvznF9XV+LG9S6Pgi5hdmF44TZ2hLrQ4rY/D147j6szWu0MmeF+dkV7gDNqghfw1yRUGQtE0COT1G8oWmrwfCssD5gPJIVA+LzYh1crQAhzMyySVKDDvevRxFE5sjss3mZF8oM54fPDmv2Jg4He2AdeFMlo3gxeSrWgZNv5b5F0AJy/O8Whjw8SKeVDNMn+1bfx0APKdmbsIHCHsIuZoHHmIDtrjAyYqVNEe55hRvrTJAPyqDrqOnthahksqsE++k9L9/X4SH8pYR8XL3zFZQoSgNMl5w5AuvcItNqTXtQeLBiw5IYl5DbYJyMhI9cZE2CetYwfEBOt23R3cM+gZ/IdS1hEtQUB5AlHkEf+8w48FGylQXdf6yYkpB8BA1Ue/X/CxkcFK3M696B0vQSx6gK6NXnHL/OjaxSRxNqG0RYMJ4iG8DmMvciSW9M7IkJgxxtAKFuvj1PEG66mp0bCndlGmge4/pDXTE/Bm/fMNGIJPfiKL83zRi1887tTUfY73G6fwlicwVzyPA/05x+rMtpAnLZ2oVf6qCshWUFxyvR+5bVVZDzHiurJoSibHAwAYqYdsZBBeTlqbuLejwbs8VwfNLoCJQvauy7R6GKwW5ninBv8VhGFHm+6xMO5ISdgGj3RXNXlZLXYBxqXO4uvGuahyeMrQ+0c1TOALiWiG70qwCsrZWfPd0yb0kJ7oA5PgucL36fdKQvSifDHW6CAqeH0DK5LQKdWi4NOjKv2LfBSYc5vsQcD95sxpfktObtMFZelTJDG4EgVTIXLaulBVQNMwUyOZUFSTjdfZz9nVHOKn5sKHqif5R8pPgEcbm5jEO/jcA2FRoSfE95nyGmLD1+0fljXiZ3K4/0fMENBEo3biRaBxCMaW/5KikbyuU95ORj4nJZx5c7saUddfeOXe5cEnHtiZUcjcR2HNTamYiKKbnzAyNamIhsWCumapkzxEHzH2Zp4g+TL3+vdw5tqpRA/aS9NEvcBSlWmkN0XC+ExIwx+xREklUogZ8m5hN2hHdDdP0dFd2WVMuOjEcffxZ1zF/jIsl0pR0YtbzqS3/D1RZdVWgmaGINRFH/FEYYpzWqtJZp4/xyxaTxELl+iuWrbVKsbGinaz6GXsfv4aBCoAIfLNSq+8++jyenGP2OyLONRgzLLrgFMCv3Y88QDOCuBqhDe3eV7Sxw0Uap/dUQSm0tn0GP1Ix1ABhTpQLkgViGXQkJn3ivhjSpoXI9dkcFABOOu9nMHVICrF4OEcpIPOvqHcWiGnrwzmngT4goHDora7/Kj2lvM5PNTV2TBLxSGUZJJ+gMNbWIfsGt1E8bcM3AzyVmSw2AueHk66PbEUPRLxGC7et5ejYBk5WPHQi30d5HSzTqLYOzPwims1vYd2hl4Kbl8QlUcUbLpmTycy+Gh2ZIo4B1QS/bHg4VtnNDZ27q44ju+oYuu+hERBOX0ROb6u0yjp57xiMHIF6X6g+KEnmQ==",
//              "algorithm": "RSA",
//              "key_length": 2048,
//              "created_at": "2020-10-19T12:13:58.771771748Z",
//              "policy": {
//                      "link": {
//                              "key-transfer": {
//                                      "href": "https://kbshostname:9443/v1/key-transfer-policies/f9af754c-3bab-4577-a98a-76acf401dc6c",
//                                      "method": "get"
//                              },
//                              "key-usage": {
//                                      "href": "https://kbshostname:9443/v1/key-usage-policies/31bed8c1-2473-4f05-a877-f554f63ecbe5",
//                                      "method": "get"
//                              }
//                      }
//              }
//      },
//      "operation": "transfer key",
//      "status": "success"
//  }
