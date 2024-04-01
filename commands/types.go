package commands

type (
	CommandType uint8
	ErrorCode   uint8
	Algorithm   uint8
	Capability  uint64
	Domain      uint16
	ObjectType  uint8
)

const (
	ResponseCommandOffset = 0x80
	ErrorResponseCode     = 0xff

	// LabelLength is the max length of a label
	LabelLength = 40

	CommandTypeEcho                    CommandType = 0x01
	CommandTypeCreateSession           CommandType = 0x03
	CommandTypeAuthenticateSession     CommandType = 0x04
	CommandTypeSessionMessage          CommandType = 0x05
	CommandTypeDeviceInfo              CommandType = 0x06
	CommandTypeReset                   CommandType = 0x08
	CommandTypeCloseSession            CommandType = 0x40
	CommandTypeStorageStatus           CommandType = 0x41
	CommandTypePutOpaque               CommandType = 0x42
	CommandTypeGetOpaque               CommandType = 0x43
	CommandTypePutAuthKey              CommandType = 0x44
	CommandTypePutAsymmetric           CommandType = 0x45
	CommandTypeGenerateAsymmetricKey   CommandType = 0x46
	CommandTypeSignDataPkcs1           CommandType = 0x47
	CommandTypeListObjects             CommandType = 0x48
	CommandTypeDecryptPkcs1            CommandType = 0x49
	CommandTypeExportWrapped           CommandType = 0x4a
	CommandTypeImportWrapped           CommandType = 0x4b
	CommandTypePutWrapKey              CommandType = 0x4c
	CommandTypeGetLogs                 CommandType = 0x4d
	CommandTypeGetObjectInfo           CommandType = 0x4e
	CommandTypePutOption               CommandType = 0x4f
	CommandTypeGetOption               CommandType = 0x50
	CommandTypeGetPseudoRandom         CommandType = 0x51
	CommandTypePutHMACKey              CommandType = 0x52
	CommandTypeHMACData                CommandType = 0x53
	CommandTypeGetPubKey               CommandType = 0x54
	CommandTypeSignDataPss             CommandType = 0x55
	CommandTypeSignDataEcdsa           CommandType = 0x56
	CommandTypeDecryptEcdh             CommandType = 0x57 // here for backwards compatibility
	CommandTypeDeriveEcdh              CommandType = 0x57
	CommandTypeDeleteObject            CommandType = 0x58
	CommandTypeDecryptOaep             CommandType = 0x59
	CommandTypeGenerateHMACKey         CommandType = 0x5a
	CommandTypeGenerateWrapKey         CommandType = 0x5b
	CommandTypeVerifyHMAC              CommandType = 0x5c
	CommandTypeOTPDecrypt              CommandType = 0x60
	CommandTypeOTPAeadCreate           CommandType = 0x61
	CommandTypeOTPAeadRandom           CommandType = 0x62
	CommandTypeOTPAeadRewrap           CommandType = 0x63
	CommandTypeAttestAsymmetric        CommandType = 0x64
	CommandTypePutOTPAeadKey           CommandType = 0x65
	CommandTypeGenerateOTPAeadKey      CommandType = 0x66
	CommandTypeSetLogIndex             CommandType = 0x67
	CommandTypeWrapData                CommandType = 0x68
	CommandTypeUnwrapData              CommandType = 0x69
	CommandTypeSignDataEddsa           CommandType = 0x6a
	CommandTypeSetBlink                CommandType = 0x6b
	CommandTypeChangeAuthenticationKey CommandType = 0x6c

	// Errors
	ErrorCodeOK                       ErrorCode = 0x00
	ErrorCodeInvalidCommand           ErrorCode = 0x01
	ErrorCodeInvalidData              ErrorCode = 0x02
	ErrorCodeInvalidSession           ErrorCode = 0x03
	ErrorCodeAuthFail                 ErrorCode = 0x04
	ErrorCodeSessionFull              ErrorCode = 0x05
	ErrorCodeSessionFailed            ErrorCode = 0x06
	ErrorCodeStorageFailed            ErrorCode = 0x07
	ErrorCodeWrongLength              ErrorCode = 0x08
	ErrorCodeInvalidPermission        ErrorCode = 0x09
	ErrorCodeLogFull                  ErrorCode = 0x0a
	ErrorCodeObjectNotFound           ErrorCode = 0x0b
	ErrorCodeInvalidID                ErrorCode = 0x0c
	ErrorCodeSSHCAConstraintViolation ErrorCode = 0x0e
	ErrorCodeInvalidOTP               ErrorCode = 0x0f
	ErrorCodeDemoMode                 ErrorCode = 0x10
	ErrorCodeObjectExists             ErrorCode = 0x11
	ErrorCodeCommandUnexecuted        ErrorCode = 0xff

	// Algorithms
	AlgorithmRSAPKCS1SHA1            Algorithm = 1
	AlgorithmRSAPKCS1SHA256          Algorithm = 2
	AlgorithmRSAPKCS1SHA384          Algorithm = 3
	AlgorithmRSAPKCS1SHA512          Algorithm = 4
	AlgorithmRSAPSSSHA1              Algorithm = 5
	AlgorithmRSAPSSSHA256            Algorithm = 6
	AlgorithmRSAPSSSHA384            Algorithm = 7
	AlgorithmRSAPSSSHA512            Algorithm = 8
	AlgorithmRSA2048                 Algorithm = 9
	AlgorithmRSA3072                 Algorithm = 10
	AlgorithmRSA4096                 Algorithm = 11
	AlgorithmP256                    Algorithm = 12
	AlgorithmP384                    Algorithm = 13
	AlgorithmP521                    Algorithm = 14
	AlgorithmSecp256k1               Algorithm = 15
	AlgorithmECBP256                 Algorithm = 16
	AlgorithmECBP384                 Algorithm = 17
	AlgorithmECBP512                 Algorithm = 18
	AlgorithmHMACSHA1                Algorithm = 19
	AlgorithmHMACSHA256              Algorithm = 20
	AlgorithmHMACSHA384              Algorithm = 21
	AlgorithmHMACSHA512              Algorithm = 22
	AlgorithmECECDSASHA1             Algorithm = 23
	AlgorithmECECDH                  Algorithm = 24
	AlgorithmRSAOAEPSHA1             Algorithm = 25
	AlgorithmRSAOAEPSHA256           Algorithm = 26
	AlgorithmRSAOAEPSHA384           Algorithm = 27
	AlgorithmRSAOAEPSHA512           Algorithm = 28
	AlgorithmAES128CCMWrap           Algorithm = 29
	AlgorithmOpaqueData              Algorithm = 30
	AlgorithmOpaqueX509Certificate   Algorithm = 31
	AlgorithmRSAMGF1SHA1             Algorithm = 32
	AlgorithmRSAMGF1SHA256           Algorithm = 33
	AlgorithmRSAMGF1SHA384           Algorithm = 34
	AlgorithmRSAMGF1SHA512           Algorithm = 35
	AlgorithmTEMPLATESSH             Algorithm = 36
	AlgorithmAES128YUBICOOTP         Algorithm = 37
	AlgorithmYubicoAESAuthentication Algorithm = 38
	AlgorithmAES192YUBICOOTP         Algorithm = 39
	AlgorithmAES256YUBICOOTP         Algorithm = 40
	AlgorithmAES192CCMWrap           Algorithm = 41
	AlgorithmAES256CCMWrap           Algorithm = 42
	AlgorithmECECDSASHA256           Algorithm = 43
	AlgorithmECECDSASHA384           Algorithm = 44
	AlgorithmECECDSASHA512           Algorithm = 45
	AlgorithmED25519                 Algorithm = 46
	AlgorithmECP224                  Algorithm = 47

	// Capabilities
	CapabilityNone                    Capability = 0x0000000000000000
	CapabilityGetOpaque               Capability = 0x0000000000000001
	CapabilityPutOpaque               Capability = 0x0000000000000002
	CapabilityPutAuthenticationKey    Capability = 0x0000000000000004
	CapabilityPutAsymmetric           Capability = 0x0000000000000008
	CapabilityAsymmetricGen           Capability = 0x0000000000000010
	CapabilityAsymmetricSignPkcs      Capability = 0x0000000000000020
	CapabilityAsymmetricSignPss       Capability = 0x0000000000000040
	CapabilityAsymmetricSignEcdsa     Capability = 0x0000000000000080
	CapabilityAsymmetricSignEddsa     Capability = 0x0000000000000100
	CapabilityAsymmetricDecryptPkcs   Capability = 0x0000000000000200
	CapabilityAsymmetricDecryptOaep   Capability = 0x0000000000000400
	CapabilityAsymmetricDecryptEcdh   Capability = 0x0000000000000800 // here for backwards compatibility
	CapabilityAsymmetricDeriveEcdh    Capability = 0x0000000000000800
	CapabilityExportWrapped           Capability = 0x0000000000001000
	CapabilityImportWrapped           Capability = 0x0000000000002000
	CapabilityPutWrapKey              Capability = 0x0000000000004000
	CapabilityGenerateWrapKey         Capability = 0x0000000000008000
	CapabilityExportableUnderWrap     Capability = 0x0000000000010000
	CapabilityPutOption               Capability = 0x0000000000020000
	CapabilityGetOption               Capability = 0x0000000000040000
	CapabilityGetRandomness           Capability = 0x0000000000080000
	CapabilityPutHmacKey              Capability = 0x0000000000100000
	CapabilityHmacKeyGenerate         Capability = 0x0000000000200000
	CapabilityHmacData                Capability = 0x0000000000400000
	CapabilityHmacVerify              Capability = 0x0000000000800000
	CapabilityAudit                   Capability = 0x0000000001000000
	CapabilitySshCertify              Capability = 0x0000000002000000
	CapabilityGetTemplate             Capability = 0x0000000004000000
	CapabilityPutTemplate             Capability = 0x0000000008000000
	CapabilityReset                   Capability = 0x0000000010000000
	CapabilityOtpDecrypt              Capability = 0x0000000020000000
	CapabilityOtpAeadCreate           Capability = 0x0000000040000000
	CapabilityOtpAeadRandom           Capability = 0x0000000080000000
	CapabilityOtpAeadRewrapFrom       Capability = 0x0000000100000000
	CapabilityOtpAeadRewrapTo         Capability = 0x0000000200000000
	CapabilityAttest                  Capability = 0x0000000400000000
	CapabilityPutOtpAeadKey           Capability = 0x0000000800000000
	CapabilityGenerateOtpAeadKey      Capability = 0x0000001000000000
	CapabilityWrapData                Capability = 0x0000002000000000
	CapabilityUnwrapData              Capability = 0x0000004000000000
	CapabilityDeleteOpaque            Capability = 0x0000008000000000
	CapabilityDeleteAuthKey           Capability = 0x0000010000000000
	CapabilityDeleteAsymmetric        Capability = 0x0000020000000000
	CapabilityDeleteWrapKey           Capability = 0x0000040000000000
	CapabilityDeleteHmacKey           Capability = 0x0000080000000000
	CapabilityDeleteTemplate          Capability = 0x0000100000000000
	CapabilityDeleteOtpAeadKey        Capability = 0x0000200000000000
	CapabilityChangeAuthenticationKey Capability = 0x0000400000000000

	// Domains
	Domain1  Domain = 0x0001
	Domain2  Domain = 0x0002
	Domain3  Domain = 0x0004
	Domain4  Domain = 0x0008
	Domain5  Domain = 0x0010
	Domain6  Domain = 0x0020
	Domain7  Domain = 0x0040
	Domain8  Domain = 0x0080
	Domain9  Domain = 0x0100
	Domain10 Domain = 0x0200
	Domain11 Domain = 0x0400
	Domain12 Domain = 0x0800
	Domain13 Domain = 0x1000
	Domain14 Domain = 0x2000
	Domain15 Domain = 0x4000
	Domain16 Domain = 0x8000

	// object types
	ObjectTypeOpaque            ObjectType = 0x01
	ObjectTypeAuthenticationKey ObjectType = 0x02
	ObjectTypeAsymmetricKey     ObjectType = 0x03
	ObjectTypeWrapKey           ObjectType = 0x04
	ObjectTypeHmacKey           ObjectType = 0x05
	ObjectTypeTemplate          ObjectType = 0x06
	ObjectTypeOtpAeadKey        ObjectType = 0x07

	// list objects params
	ListObjectParamID           uint8 = 0x01
	ListObjectParamType         uint8 = 0x02
	ListObjectParamDomains      uint8 = 0x03
	ListObjectParamCapabilities uint8 = 0x04
	ListObjectParamAlgorithm    uint8 = 0x05
	ListObjectParamLabel        uint8 = 0x06
)

// CapabilityPrimitiveFromSlice OR's all the capabilitites together.
func CapabilityPrimitiveFromSlice(capabilitites []uint64) uint64 {
	var primitive uint64
	for _, c := range capabilitites {
		primitive |= c
	}
	return primitive
}
