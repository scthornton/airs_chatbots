# Environment Configuration Template
# Copy this file to .env and fill in your actual values
# DO NOT commit .env to version control

# =============================================================================
# PALO ALTO NETWORKS AI RUNTIME SECURITY CONFIGURATION
# =============================================================================

# API Key from Strata Cloud Manager
# Get this from: https://apps.paloaltonetworks.com/
PANW_AI_SEC_API_KEY=your_palo_alto_api_key_here

# Security Profile Name (configured in Strata Cloud Manager)
PANW_AI_SEC_PROFILE=your_security_profile_name

# API Endpoint (choose based on your region)
# US: https://service.api.aisecurity.paloaltonetworks.com
# EU: https://service-de.api.aisecurity.paloaltonetworks.com
PANW_AI_SEC_ENDPOINT=https://service.api.aisecurity.paloaltonetworks.com

# =============================================================================
# AZURE OPENAI CONFIGURATION
# =============================================================================

# Azure OpenAI API Key
# Get this from Azure Portal > Your OpenAI Resource > Keys and Endpoint
AZURE_OPENAI_API_KEY=your_azure_openai_api_key_here

# Azure OpenAI Endpoint
# Format: https://your-resource-name.openai.azure.com/
AZURE_OPENAI_ENDPOINT=https://your-resource-name.openai.azure.com/

# Azure OpenAI Deployment Name
# This is the name you gave to your model deployment in Azure OpenAI Studio
AZURE_OPENAI_DEPLOYMENT_NAME=your_deployment_name

# Azure OpenAI API Version (usually you can keep this as is)
AZURE_OPENAI_API_VERSION=2024-02-01

# =============================================================================
# OPTIONAL CONFIGURATION
# =============================================================================

# Application Environment
ENVIRONMENT=development

# Logging Level (DEBUG, INFO, WARNING, ERROR)
LOG_LEVEL=INFO

# Maximum conversation history to maintain
MAX_CONVERSATION_HISTORY=20

# Request timeout in seconds
REQUEST_TIMEOUT=30

# =============================================================================
# SECURITY NOTES
# =============================================================================
# 
# 1. Never commit this file with real credentials to version control
# 2. Add .env to your .gitignore file
# 3. Use different .env files for different environments (dev, staging, prod)
# 4. Consider using Azure Key Vault or AWS Secrets Manager for production
# 5. Rotate your API keys regularly
# 6. Use minimum required permissions for your API keys
#
# =============================================================================
