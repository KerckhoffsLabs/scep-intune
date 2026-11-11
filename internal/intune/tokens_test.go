package intune

import "testing"

const publicHost = "https://login.microsoftonline.com/"

func TestCredentialOptionsDefaultIsNil(t *testing.T) {
	for _, host := range []string{"", publicHost, "HTTPS://LOGIN.MicrosoftOnline.com/"} {
		if opts := credentialOptions(host, ""); opts != nil {
			t.Errorf("credentialOptions(%q, \"\") = %+v, want nil (SDK defaults, instance discovery on)", host, opts)
		}
	}
}

func TestCredentialOptionsCustomAuthority(t *testing.T) {
	opts := credentialOptions("https://mock.example/", "")
	if opts == nil {
		t.Fatal("credentialOptions returned nil for a custom authority")
	}
	if got := opts.Cloud.ActiveDirectoryAuthorityHost; got != "https://mock.example/" {
		t.Errorf("authority host = %q", got)
	}
	if !opts.DisableInstanceDiscovery {
		t.Error("instance discovery must be disabled for a custom authority")
	}
}

// AZURE_AUTHORITY_HOST is read by the Azure SDK only when the options leave the
// cloud unset. With the default authority configured, a differing env value
// must not win: the options pin the commercial host and keep instance
// discovery on.
func TestCredentialOptionsIgnoresConflictingEnvAuthority(t *testing.T) {
	opts := credentialOptions(publicHost, "https://login.microsoftonline.us/")
	if opts == nil {
		t.Fatal("want explicit options pinning the configured authority")
	}
	if got := opts.Cloud.ActiveDirectoryAuthorityHost; got != publicHost {
		t.Errorf("authority host = %q, want %q", got, publicHost)
	}
	if opts.DisableInstanceDiscovery {
		t.Error("instance discovery must stay on for the commercial authority")
	}
}

func TestCredentialOptionsMatchingEnvAuthorityIsNil(t *testing.T) {
	if opts := credentialOptions(publicHost, "https://login.microsoftonline.com"); opts != nil {
		t.Errorf("env equal to the default (modulo slash) should keep SDK defaults, got %+v", opts)
	}
}

func TestEnvAuthorityConflicts(t *testing.T) {
	for _, tc := range []struct {
		configured, env string
		want            bool
	}{
		{publicHost, "", false},
		{publicHost, "https://LOGIN.microsoftonline.com", false},
		{publicHost, "https://login.microsoftonline.us/", true},
		{"https://mock.example/", "https://login.microsoftonline.us/", true},
	} {
		if got := EnvAuthorityConflicts(tc.configured, tc.env); got != tc.want {
			t.Errorf("EnvAuthorityConflicts(%q, %q) = %v, want %v", tc.configured, tc.env, got, tc.want)
		}
	}
}

func TestKnownMicrosoftAuthority(t *testing.T) {
	for host, want := range map[string]bool{
		"https://login.microsoftonline.com/": true,
		"https://LOGIN.microsoftonline.us":   true,
		"https://login.chinacloudapi.cn/":    true,
		"https://127.0.0.1:8444/":            false,
		"https://intune-mock:8443/":          false,
	} {
		if got := KnownMicrosoftAuthority(host); got != want {
			t.Errorf("KnownMicrosoftAuthority(%q) = %v, want %v", host, got, want)
		}
	}
}
