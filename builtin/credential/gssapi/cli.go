package userpass

import (
	"encoding/base64"
	"fmt"
	"net"
	"strings"

	"github.com/apcera/gssapi"
	"github.com/hashicorp/vault/api"
	"github.com/mitchellh/mapstructure"
)

type CLIHandler struct{}

func (h *CLIHandler) Auth(c *api.Client, m map[string]string) (string, error) {
	var data struct {
		Mount       string `mapstructure:"mount"`
		ServiceName string `mapstructure:"servicename"`
	}
	if err := mapstructure.WeakDecode(m, &data); err != nil {
		return "", err
	}

	if data.Mount == "" {
		data.Mount = "gssapi"
	}

	if data.ServiceName == "" {
		host, _, err := net.SplitHostPort(c.NewRequest("", "").URL.Host)
		if err != nil {
			return "", err
		}
		data.ServiceName = "vault/" + host
		fmt.Println("Auto-Generated service name:", data.ServiceName)
		data.ServiceName = "HTTP/foreman.na.intgdc.com"
	}

	token, err := h.getGssAPIToken(data.ServiceName)
	if err != nil {
		return "", err
	}
	tokenInString := base64.StdEncoding.EncodeToString(token)

	options := map[string]interface{}{}
	options["GssAPIToken"] = tokenInString

	path := fmt.Sprintf("auth/%s/login", data.Mount)
	secret, err := c.Logical().Write(path, options)
	if err != nil {
		return "", err
	}
	if secret == nil {
		return "", fmt.Errorf("empty response from credential provider")
	}

	return secret.Auth.ClientToken, nil
}

func (h *CLIHandler) Help() string {
	help := `
The "gssapi" credential provider allows you to authenticate using underlying system (most probably Kerberos).
You need to run "kinit" before use of this method. If servicename is not specified, credential backend try to build service
from name "vault" and URL specified as Vault server.

    Example: vault auth -method=gssapi \
	-servicename=<gssapi service name>

	`
	return strings.TrimSpace(help)
}

func (h *CLIHandler) getGssAPIToken(serviceName string) ([]byte, error) {
	options := &(gssapi.Options{})
	lib, err := gssapi.Load(options)
	if err != nil {
		fmt.Println("Gssapi load failed", err)
		return nil, err
	}
	name := h.prepareServiceName(serviceName, lib)
	_, _, token, _, _, err := lib.InitSecContext(
		lib.GSS_C_NO_CREDENTIAL,
		nil,
		name,
		lib.GSS_C_NO_OID,
		0,
		0,
		lib.GSS_C_NO_CHANNEL_BINDINGS,
		lib.GSS_C_NO_BUFFER)
	fmt.Println("Error:", err)
	fmt.Println("Token length: ", len(token.Bytes()))

	return token.Bytes(), err
}

func (h *CLIHandler) prepareServiceName(sname string, lib *gssapi.Lib) *gssapi.Name {
	if sname == "" {
		fmt.Println("Need a --service-name")
	}

	nameBuf, err := lib.MakeBufferString(sname)
	if err != nil {
		fmt.Println(err)
	}
	defer nameBuf.Release()

	name, err := nameBuf.Name(lib.GSS_KRB5_NT_PRINCIPAL_NAME)
	if err != nil {
		fmt.Println(err)
	}
	if name.String() != sname {
		fmt.Printf("name: got %q, expected %q", name.String(), sname)
	}

	return name
}
