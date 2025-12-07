/**
 * Attestation Test Fixtures Index
 *
 * Exports all attestation mock data for Android and iOS platforms.
 * Use these fixtures when testing device attestation verification logic.
 */

// Android Hardware Key Attestation
export {
  // Constants
  ATTESTATION_EXTENSION_OID,
  AndroidSecurityLevel,
  AttestationVersion,
  VerifiedBootState,
  // Mock CAs
  MOCK_GOOGLE_ROOT_CA,
  MOCK_INTERMEDIATE_CA,
  MOCK_GRAPHENEOS_ROOT_CA,
  // Types
  type AttestationExtension,
  type AuthorizationList,
  type RootOfTrust,
  type MockAttestationOptions,
  // Generators
  generateMockAndroidAttestation,
  createTEEAttestation,
  createStrongBoxAttestation,
  createUnlockedBootloaderAttestation,
  createWrongChallengeAttestation,
  createGrapheneOSAttestation,
  // Validators
  validateMockCertChain,
} from './androidAttestation';

// iOS App Attest
export {
  // Constants
  ATTESTATION_FORMAT,
  APPLE_APP_ATTEST_AAGUID,
  APPLE_APP_ATTESTATION_ROOT_CA_OID,
  AppAttestEnvironment,
  // Mock CAs
  MOCK_APPLE_ROOT_CA,
  MOCK_APPLE_INTERMEDIATE_CA,
  // Types
  type AuthenticatorData,
  type AttestationStatement,
  type AttestationObject,
  type MockiOSAttestationOptions,
  type AssertionOptions,
  // Generators
  generateMockiOSAttestation,
  createProductionAttestation,
  createDevelopmentAttestation,
  createWrongAppIdAttestation,
  generateMockAssertion,
  // Helpers
  createClientDataHash,
  computeNonce,
  validateCounter,
} from './iosAttestation';
