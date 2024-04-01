package softmodule

import (
	"crypto"
	"crypto/cipher"
	"hash"

	"github.com/certusone/yubihsm-go/authkey"
	"github.com/certusone/yubihsm-go/commands"
)

type Session struct {
	EncKey  []byte
	MACKey  []byte
	RMACKey []byte
}

type Capabilities commands.Capability

func (c Capabilities) Has(capability commands.Capability) bool {
	return (commands.Capability(c) & capability) != 0
}

func (c Capabilities) Add(capability ...commands.Capability) Capabilities {
	r := commands.Capability(c)
	for _, v := range capability {
		r |= v
	}
	return Capabilities(r)
}

var allCapabilities = Capabilities(commands.CapabilityNone).Add(
	commands.CapabilityGetOpaque,
	commands.CapabilityPutOpaque,
	commands.CapabilityPutAuthenticationKey,
	commands.CapabilityPutAsymmetric,
	commands.CapabilityAsymmetricGen,
	commands.CapabilityAsymmetricSignPkcs,
	commands.CapabilityAsymmetricSignPss,
	commands.CapabilityAsymmetricSignEcdsa,
	commands.CapabilityAsymmetricSignEddsa,
	commands.CapabilityAsymmetricDecryptPkcs,
	commands.CapabilityAsymmetricDecryptOaep,
	commands.CapabilityAsymmetricDecryptEcdh,
	commands.CapabilityAsymmetricDeriveEcdh,
	commands.CapabilityExportWrapped,
	commands.CapabilityImportWrapped,
	commands.CapabilityPutWrapKey,
	commands.CapabilityGenerateWrapKey,
	commands.CapabilityExportableUnderWrap,
	commands.CapabilityPutOption,
	commands.CapabilityGetOption,
	commands.CapabilityGetRandomness,
	commands.CapabilityPutHmacKey,
	commands.CapabilityHmacKeyGenerate,
	commands.CapabilityHmacData,
	commands.CapabilityHmacVerify,
	commands.CapabilityAudit,
	commands.CapabilitySshCertify,
	commands.CapabilityGetTemplate,
	commands.CapabilityPutTemplate,
	commands.CapabilityReset,
	commands.CapabilityOtpDecrypt,
	commands.CapabilityOtpAeadCreate,
	commands.CapabilityOtpAeadRandom,
	commands.CapabilityOtpAeadRewrapFrom,
	commands.CapabilityOtpAeadRewrapTo,
	commands.CapabilityAttest,
	commands.CapabilityPutOtpAeadKey,
	commands.CapabilityGenerateOtpAeadKey,
	commands.CapabilityWrapData,
	commands.CapabilityUnwrapData,
	commands.CapabilityDeleteOpaque,
	commands.CapabilityDeleteAuthKey,
	commands.CapabilityDeleteAsymmetric,
	commands.CapabilityDeleteWrapKey,
	commands.CapabilityDeleteHmacKey,
	commands.CapabilityDeleteTemplate,
	commands.CapabilityDeleteOtpAeadKey,
	commands.CapabilityChangeAuthenticationKey,
)

type Domains commands.Domain

func (d Domains) Has(domain commands.Domain) bool {
	return (commands.Domain(d) & domain) != 0
}

func (d Domains) Add(domain ...commands.Domain) Domains {
	r := commands.Domain(d)
	for _, v := range domain {
		r |= v
	}
	return Domains(r)
}

var allDomains = Domains(0).Add(
	commands.Domain1,
	commands.Domain2,
	commands.Domain3,
	commands.Domain4,
	commands.Domain5,
	commands.Domain6,
	commands.Domain7,
	commands.Domain8,
	commands.Domain9,
	commands.Domain10,
	commands.Domain11,
	commands.Domain12,
	commands.Domain13,
	commands.Domain14,
	commands.Domain15,
	commands.Domain16,
)

type PrivateKey interface {
	Public() crypto.PublicKey
	Equal(x crypto.PrivateKey) bool
}

type Object struct {
	Label        [40]byte
	Domains      Domains
	Capabilities Capabilities
}

type AuthenticationKey struct {
	Object
	AuthKey               authkey.AuthKey
	DelegatedCapabilities Capabilities
}

type AsymmetricKey struct {
	Object
	Key PrivateKey
}

type HMACKey struct {
	Object
	HMAC hash.Hash
}

type Opaque struct {
	Object
	Data []byte
}

type OTPAeadKey struct {
	Object
	Key cipher.AEAD
}

type SymmetricKey struct {
	Object
	Key cipher.Block
}

type Template struct {
	Object
	Data []byte
}

type WrapKey struct {
	Object
	Key []byte
}
