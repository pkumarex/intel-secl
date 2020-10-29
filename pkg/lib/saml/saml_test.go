/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package saml

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"github.com/stretchr/testify/assert"
	"math/big"
	"testing"
	"time"

	"github.com/beevik/etree"
)

func TestGenXMLTree(t *testing.T) {
	testMap := map[string]string{
		"test-field-1": "test-val-1",
		"test-field-2": "test-val-2",
		"test-field-3": "test-val-3",
		"test-field-4": "test-val-4",
		"test-field-5": "test-val-5",
	}
	f := NewMapFormatter(testMap)
	root, err := f.generateXMLTree(IssuerConfiguration{
		IssuerName:        "http://idp.test.com/metadata",
		IssuerServiceName: "test-idp",
		ValiditySeconds:   100,
	})
	if err != nil || root == nil {
		t.Fatal("xml tree generate failed")
	}

	conditions := root.FindElement(conditionTag)
	audienceRestriction := audienceRestrictionXML()
	audience := audienceXML("https://sp.test.com/test/service/endpoint")
	audienceRestriction.AddChild(audience)
	conditions.AddChild(audienceRestriction)

	docBeforeSign := etree.NewDocument()
	docBeforeSign.SetRoot(root)
	docStr, err := docBeforeSign.WriteToString()
	if err != nil {
		t.Error("Failed to create unsigned document:", err.Error())
		t.Fail()
	}
	t.Log("Unsigned document:")
	t.Log(docStr)

	// test response tree
	resp := responseXML("Some_Report_ID", "https://sp.test.com/test/service/endpoint", "Some_Session_Token", time.Now().UTC().Format(time.RFC3339))
	issuer := issuerXML("http://idp.test.com/metadata")
	status := statusXML(statusCodeSuccess)
	resp.AddChild(issuer)
	resp.AddChild(status)
	resp.AddChild(root)

	respDoc := etree.NewDocument()
	respDoc.SetRoot(resp)
	respStr, err := respDoc.WriteToString()
	if err != nil {
		t.Error("Failed to create unsigned document:", err.Error())
		t.Fail()
	}
	t.Log("SAML response")
	t.Log(respStr)
}

func genKeyAndCert() (*rsa.PrivateKey, *x509.Certificate, error) {
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		return nil, nil, err
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(0),
		NotBefore:    now.Add(-5 * time.Minute),
		NotAfter:     now.Add(365 * 24 * time.Hour),

		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{},
		BasicConstraintsValid: true,
	}
	certDer, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	cert, err := x509.ParseCertificate(certDer)
	if err != nil {
		return nil, nil, err
	}
	return key, cert, nil
}

func TestFullGenAndSign(t *testing.T) {
	testMap := map[string]string{
		"test-field-1": "test-val-1",
		"test-field-2": "test-val-2",
		"test-field-3": "test-val-3",
		"test-field-4": "test-val-4",
		"test-field-5": "test-val-5",
	}
	k, c, err := genKeyAndCert()
	if err != nil {
		t.Fatal("Failed to generate rsa key:", err.Error())
	}
	testIc := IssuerConfiguration{
		IssuerName:        "http://idp.test.com/metadata.php",
		IssuerServiceName: "test-idp",
		ValiditySeconds:   100,
		PrivateKey:        k,
		Certificate:       c,
	}
	testSAML, err := NewSAML(testIc)
	if err != nil {
		t.Fatal("Failed to create saml object:", err.Error())
	}
	testFormatter := NewMapFormatter(testMap)
	assertion, err := testSAML.GenerateSamlAssertion(testFormatter)
	if err != nil {
		t.Fatal("Failed to create saml assertion:", err.Error())
	}
	t.Log(assertion)

	// validate
	v, err := ValidateSamlAssertion(assertion, c)
	if err != nil {
		t.Fatal("Failed to validate saml assertion:", err.Error())
	}
	doc := etree.NewDocument()
	doc.SetRoot(v)
	str, err := doc.WriteToString()
	if err != nil {
		t.Fatal("Failed to write validated saml assertion to string", err.Error())
	}
	t.Log(str)
}

func TestFullGenWithoutSign(t *testing.T) {
	testMap := map[string]string{
		"test-field-1": "test-val-1",
		"test-field-2": "test-val-2",
		"test-field-3": "test-val-3",
		"test-field-4": "test-val-4",
		"test-field-5": "test-val-5",
	}
	k, c, err := genKeyAndCert()
	if err != nil {
		t.Fatal("Failed to generate rsa key:", err.Error())
	}
	testIc := IssuerConfiguration{
		IssuerName:        "http://idp.test.com/metadata.php",
		IssuerServiceName: "test-idp",
		ValiditySeconds:   100,
		PrivateKey:        k,
		Certificate:       c,
	}
	testFormatter := NewMapFormatter(testMap)
	ss := legacySamlSigner{
		issuerConfig:     testIc,
		validityDuration: time.Second * time.Duration(testIc.ValiditySeconds),
		certBytes:        testIc.Certificate.Raw,
	}
	assertion, err := GenerateSamlAssertionWithoutSig(testFormatter, ss)
	if err != nil {
		t.Fatal("Failed to create saml assertion:", err.Error())
	}
	t.Log(assertion)

	// validate legacy saml assertion
	_, err = ValidateLegacySamlAssertion(assertion, c)
	assert.NotNil(t, err)
	assert.Error(t, err)
}
