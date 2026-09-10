package saml2aws

import (
	"os"
	"testing"
	"time"
)

func TestSAMLExtractorsEdgeCases(t *testing.T) {
	tests := []struct {
		name string
		xml  string
		want func(t *testing.T, data []byte)
	}{
		{
			name: "reordered elements and namespaces",
			xml: `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" Destination="https://example.test/saml">
				<samlp:Status><samlp:StatusCode Value="ok"/></samlp:Status>
				<Assertion xmlns="urn:oasis:names:tc:SAML:2.0:assertion">
					<AttributeStatement>
						<saml2:Attribute xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" Name="https://aws.amazon.com/SAML/Attributes/SessionDuration"><saml2:AttributeValue>3600</saml2:AttributeValue></saml2:Attribute>
						<Attribute Name="https://aws.amazon.com/SAML/Attributes/Role"><AttributeValue>role-one</AttributeValue><AttributeValue>role-two</AttributeValue></Attribute>
					</AttributeStatement>
				</Assertion>
			</samlp:Response>`,
			want: func(t *testing.T, data []byte) {
				duration, err := ExtractSessionDuration(data)
				if err != nil || duration != 3600 {
					t.Fatalf("ExtractSessionDuration() = %d, %v; want 3600, nil", duration, err)
				}
				roles, err := ExtractAwsRoles(data)
				if err != nil || len(roles) != 2 || roles[0] != "role-one" || roles[1] != "role-two" {
					t.Fatalf("ExtractAwsRoles() = %#v, %v; want both roles", roles, err)
				}
				destination, err := ExtractDestinationURL(data)
				if err != nil || destination != "https://example.test/saml" {
					t.Fatalf("ExtractDestinationURL() = %q, %v; want destination", destination, err)
				}
			},
		},
		{
			name: "recipient fallback",
			xml:  `<Response><Assertion><Subject><SubjectConfirmation><SubjectConfirmationData Recipient="https://example.test/fallback" NotOnOrAfter="2030-01-02T03:04:05Z"/></SubjectConfirmation></Subject></Assertion></Response>`,
			want: func(t *testing.T, data []byte) {
				destination, err := ExtractDestinationURL(data)
				if err != nil || destination != "https://example.test/fallback" {
					t.Fatalf("ExtractDestinationURL() = %q, %v; want recipient fallback", destination, err)
				}
				expires, err := ExtractMFATokenExpiryTime(data)
				if err != nil || !expires.Equal(time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)) {
					t.Fatalf("ExtractMFATokenExpiryTime() = %v, %v; want fixed time", expires, err)
				}
			},
		},
		{
			name: "missing assertion and attributes",
			xml:  `<Response><Status/></Response>`,
			want: func(t *testing.T, data []byte) {
				if _, err := ExtractAwsRoles(data); err != ErrMissingAssertion {
					t.Fatalf("ExtractAwsRoles() error = %v; want %v", err, ErrMissingAssertion)
				}
				if _, err := ExtractSessionDuration(data); err != ErrMissingAssertion {
					t.Fatalf("ExtractSessionDuration() error = %v; want %v", err, ErrMissingAssertion)
				}
				if _, err := ExtractDestinationURL(data); err == nil {
					t.Fatal("ExtractDestinationURL() unexpectedly accepted response without destination")
				}
				if _, err := ExtractMFATokenExpiryTime(data); err == nil {
					t.Fatal("ExtractMFATokenExpiryTime() unexpectedly accepted response without confirmation data")
				}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) { test.want(t, []byte(test.xml)) })
	}
}

func TestSAMLExtractorsMalformedInput(t *testing.T) {
	for _, input := range []string{"", "not-base64!!!", "PHNhbWxwOlJlc3BvbnNlPj", "<Response", "\x00\xff"} {
		t.Run(input, func(t *testing.T) {
			data := []byte(input)
			if _, err := ExtractSessionDuration(data); err == nil {
				t.Error("ExtractSessionDuration() unexpectedly succeeded")
			}
			if _, err := ExtractDestinationURL(data); err == nil {
				t.Error("ExtractDestinationURL() unexpectedly succeeded")
			}
			if _, err := ExtractMFATokenExpiryTime(data); err == nil {
				t.Error("ExtractMFATokenExpiryTime() unexpectedly succeeded")
			}
			if _, err := ExtractAwsRoles(data); err == nil {
				t.Error("ExtractAwsRoles() unexpectedly succeeded")
			}
		})
	}
}

func FuzzSAMLExtractorsNoPanic(f *testing.F) {
	for _, name := range []string{"testdata/assertion.xml", "testdata/assertion_no_destination.xml", "testdata/assertion_invalid_date.xml", "testdata/notxml.xml"} {
		data, err := os.ReadFile(name)
		if err != nil {
			f.Fatalf("read %s: %v", name, err)
		}
		f.Add(data)
	}
	for _, seed := range []string{"", "not-base64!!!", "<Response/>", "\x00\xff", "<Response><Assertion><AttributeStatement/></Assertion></Response>"} {
		f.Add([]byte(seed))
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = ExtractSessionDuration(data)
		_, _ = ExtractDestinationURL(data)
		_, _ = ExtractMFATokenExpiryTime(data)
		_, _ = ExtractAwsRoles(data)
	})
}
