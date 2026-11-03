# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Abhishek Rai. VCF Enterprise MCP: https://github.com/abhishekaryan23/vcf-ent-mcp
"""
Enterprise Secret Management and Zero-Trust Credential Broker Package.
Provides pluggable, policy-governed secret resolution across local encrypted stores,
environment variables, HashiCorp Vault, Azure Key Vault, and AWS Secrets Manager.
"""

from vcf_enterprise_mcp.secrets.models import (
    SecretValue,
    SecretMaterial,
    SecretReference,
    RequestContext,
    SecretProviderHealth,
    SecretMetadata,
    CredentialPolicy,
)
from vcf_enterprise_mcp.secrets.base import (
    SecretProvider,
    SecretProviderException,
    MissingCredentialException,
    CredentialPolicyViolationException,
    CredentialDecryptionException,
)
from vcf_enterprise_mcp.secrets.environment import EnvironmentSecretProvider
from vcf_enterprise_mcp.secrets.local_encrypted import (
    LocalEncryptedSecretProvider,
    LocalKeyProtector,
)
from vcf_enterprise_mcp.secrets.vault import HashiCorpVaultSecretProvider
from vcf_enterprise_mcp.secrets.azure_keyvault import AzureKeyVaultSecretProvider
from vcf_enterprise_mcp.secrets.aws_secrets import AWSSecretsManagerProvider
from vcf_enterprise_mcp.secrets.cyberark import (
    CyberArkCCPSecretProvider,
    CyberArkConfig,
    CyberArkOperatingMode,
)
from vcf_enterprise_mcp.secrets.registry import (
    SecretProviderRegistry,
    get_default_secret_registry,
    set_default_secret_registry,
)

__all__ = [
    "SecretValue",
    "SecretMaterial",
    "SecretReference",
    "RequestContext",
    "SecretProviderHealth",
    "SecretMetadata",
    "CredentialPolicy",
    "SecretProvider",
    "SecretProviderException",
    "MissingCredentialException",
    "CredentialPolicyViolationException",
    "CredentialDecryptionException",
    "EnvironmentSecretProvider",
    "LocalEncryptedSecretProvider",
    "LocalKeyProtector",
    "HashiCorpVaultSecretProvider",
    "AzureKeyVaultSecretProvider",
    "AWSSecretsManagerProvider",
    "CyberArkCCPSecretProvider",
    "CyberArkConfig",
    "CyberArkOperatingMode",
    "SecretProviderRegistry",
    "get_default_secret_registry",
    "set_default_secret_registry",
]
