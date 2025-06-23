# ===========================================================================
# PYTHON SDK SECURE AI CHATBOT
# ===========================================================================
# This script uses the Palo Alto Networks AI Security Python SDK
# combined with direct HTTP scanning for a complete SDK experience.
#
# WORKFLOW: User Input → Python SDK Security Scan → AI Processing → Response
# ===========================================================================

import requests
import json
import os
import uuid
import httpx
import asyncio
import time
from openai import AzureOpenAI

# Import the real Palo Alto Networks AI Security SDK
try:
    import aisecurity
    from aisecurity.generated_openapi_client import AiProfile, ScanRequestContentsInner
    from aisecurity.exceptions import AISecSDKException
    SDK_AVAILABLE = True
    print("✅ Palo Alto Networks AI Security SDK imported successfully")
except ImportError as e:
    SDK_AVAILABLE = False
    print(f"❌ Failed to import Palo Alto Networks AI Security SDK: {e}")
    print("   Install with: pip install pan-aisecurity")


class SDKSecurityScanner:
    """
    SDK SECURITY SCANNER

    Uses the Palo Alto Networks Python SDK for configuration and authentication,
    combined with direct HTTP requests for scanning functionality.
    """

    def __init__(self, api_key, profile_name, api_endpoint=None, num_retries=3):
        self.api_key = api_key
        self.profile_name = profile_name
        self.api_endpoint = api_endpoint or "https://service.api.aisecurity.paloaltonetworks.com"
        self.num_retries = num_retries

        # Initialize the SDK
        aisecurity.init(
            api_key=api_key,
            api_endpoint=self.api_endpoint,
            num_retries=num_retries
        )

        # Get configuration from the SDK
        self.config = aisecurity.global_configuration

        # Threat analysis mapping
        self.threat_categories = {
            'prompt_injection': 'Prompt Injection Attack',
            'injection': 'Prompt Injection Attack',
            'agent': 'AI Agent Manipulation',
            'url_cats': 'Malicious URL Detection',
            'dlp': 'Data Loss Prevention',
            'toxic_content': 'Toxic Content',
            'toxicity': 'Toxic Content',
        }

    def create_scan_request(self, prompt):
        """Create a scan request using SDK models"""
        try:
            # Use SDK models
            ai_profile_data = {"profile_name": self.profile_name}
            content_data = {"prompt": prompt}

            # Create the request data structure
            request_data = {
                "tr_id": str(uuid.uuid4()),
                "ai_profile": ai_profile_data,
                "contents": [content_data]
            }

            return request_data

        except Exception as e:
            raise AISecSDKException(f"Failed to create scan request: {e}")

    def execute_scan_request(self, request_data):
        """Execute scan request using SDK configuration"""
        url = f"{self.config.api_endpoint}/v1/scan/sync/request"

        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "x-pan-token": self.config.api_key,
            "User-Agent": "PAN-AI-Security-SDK/1.0.0"
        }

        for attempt in range(self.num_retries + 1):
            try:
                if attempt > 0:
                    wait_time = 2 ** (attempt - 1)  # Exponential backoff
                    print(
                        f"   🔄 Retry attempt {attempt}/{self.num_retries} (waiting {wait_time}s)")
                    time.sleep(wait_time)

                print(
                    f"   📡 Sending SDK security scan request (attempt {attempt + 1})")
                response = requests.post(
                    url, headers=headers, json=request_data, timeout=30)
                response.raise_for_status()

                result = response.json()
                print(f"   ✅ SDK security scan completed successfully")
                return result

            except requests.exceptions.HTTPError as e:
                if e.response.status_code == 401:
                    raise AISecSDKException(
                        f"Authentication failed: Invalid API key")
                elif e.response.status_code == 404:
                    raise AISecSDKException(
                        f"Profile not found: {self.profile_name}")
                elif attempt == self.num_retries:
                    raise AISecSDKException(
                        f"HTTP Error after {self.num_retries} retries: {e}")

            except requests.exceptions.ConnectionError as e:
                if attempt == self.num_retries:
                    raise AISecSDKException(
                        f"Connection failed after {self.num_retries} retries: {e}")

            except requests.exceptions.Timeout as e:
                if attempt == self.num_retries:
                    raise AISecSDKException(
                        f"Request timeout after {self.num_retries} retries: {e}")

    def sync_scan(self, prompt):
        """
        Perform synchronous security scan using Python SDK

        Args:
            prompt (str): The user's message to scan

        Returns:
            dict: Comprehensive scan results
        """
        start_time = time.time()

        print(f"🔍 Python SDK Security Scan Starting...")
        print(f"   Content: '{prompt[:50]}...' ({len(prompt)} characters)")
        print(f"   SDK Profile: {self.profile_name}")
        print(f"   SDK Endpoint: {self.config.api_endpoint}")

        # Create scan request using SDK models
        request_data = self.create_scan_request(prompt)
        print(f"   Transaction ID: {request_data['tr_id']}")

        # Execute scan request
        scan_result = self.execute_scan_request(request_data)

        # Calculate scan time
        scan_time = (time.time() - start_time) * 1000
        scan_result['scan_time_ms'] = scan_time

        return scan_result

    async def async_scan(self, prompt):
        """
        Perform asynchronous security scan

        Args:
            prompt (str): The user's message to scan

        Returns:
            dict: Comprehensive scan results
        """
        # Run sync scan in executor to avoid blocking
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self.sync_scan, prompt)

    def display_enhanced_results(self, scan_result):
        """Display comprehensive SDK-style scan results"""

        print("\n📋 PYTHON SDK SCAN RESULTS:")
        print("=" * 50)
        print(
            f"Overall Classification: {scan_result.get('category', 'Unknown')}")
        print(f"Recommended Action: {scan_result.get('action', 'Unknown')}")
        print(f"Profile Used: {scan_result.get('profile_name', 'Unknown')}")
        print(f"Profile ID: {scan_result.get('profile_id', 'Unknown')}")
        print(f"Scan Time: {scan_result.get('scan_time_ms', 0):.1f}ms")
        print(f"Transaction ID: {scan_result.get('tr_id', 'Unknown')}")
        print(f"Report ID: {scan_result.get('report_id', 'Unknown')}")
        print(f"Scan ID: {scan_result.get('scan_id', 'Unknown')}")

        print(f"\n⚠️  DETAILED THREAT ANALYSIS:")
        print("=" * 50)

        threats_found = False

        # Debug information
        print(f"🔍 SDK SCAN DETAILS:")
        print(f"   Category: {scan_result.get('category')}")
        print(f"   Action: {scan_result.get('action')}")
        print(f"   Prompt threats: {scan_result.get('prompt_detected', {})}")
        print(
            f"   Response threats: {scan_result.get('response_detected', {})}")

        # Analyze prompt-based threats
        prompt_detected = scan_result.get('prompt_detected', {})
        if prompt_detected:
            print(f"\n🎯 PROMPT-LEVEL THREATS:")
            for threat_type, detected in prompt_detected.items():
                if detected:
                    threat_name = self.threat_categories.get(
                        threat_type, threat_type.replace('_', ' ').title())
                    print(f"   🔴 {threat_name}")
                    threats_found = True

                    # Provide specific guidance
                    if threat_type in ['injection', 'prompt_injection']:
                        print(f"      └─ Malicious instruction patterns detected")
                        print(
                            f"      └─ Recommendation: Rephrase without command-like language")
                    elif threat_type == 'agent':
                        print(f"      └─ AI agent manipulation attempt detected")
                        print(
                            f"      └─ Recommendation: Remove role-playing or identity claims")
                    elif threat_type in ['toxicity', 'toxic_content']:
                        print(f"      └─ Harmful or offensive content identified")
                        print(
                            f"      └─ Recommendation: Use respectful, appropriate language")
                    elif threat_type == 'url_cats':
                        print(f"      └─ Malicious URL detected in prompt")
                        print(f"      └─ Recommendation: Remove suspicious links")
                    elif threat_type == 'dlp':
                        print(f"      └─ Sensitive data exposure risk")
                        print(
                            f"      └─ Recommendation: Remove personal/confidential information")

        # Analyze response-based threats
        response_detected = scan_result.get('response_detected', {})
        if response_detected:
            print(f"\n🎯 RESPONSE-LEVEL THREATS:")
            for threat_type, detected in response_detected.items():
                if detected:
                    threat_name = self.threat_categories.get(
                        threat_type, threat_type.replace('_', ' ').title())
                    print(f"   🔴 {threat_name}")
                    threats_found = True

        # Overall threat assessment
        if scan_result.get('category') == 'malicious' and not threats_found:
            print(f"   🔴 GENERAL SECURITY VIOLATION")
            print(f"      └─ Content flagged as malicious by security policies")
            threats_found = True

        if not threats_found:
            print("   ✅ No security threats detected")
            print("   ✅ Content approved for AI processing")

        print("=" * 50)


async def main():
    """
    MAIN ASYNC CHATBOT CONTROLLER WITH PYTHON SDK

    Demonstrates production-grade usage of the Palo Alto Networks
    AI Security Python SDK with comprehensive scanning capabilities.
    """

    print("🚀 INITIALIZING PYTHON SDK SECURE AI CHATBOT")
    print("=" * 60)
    print("Security Layer: Palo Alto Networks AI Security Python SDK")
    print("AI Processing: Azure OpenAI GPT Models")
    print("Features: Python SDK, Async/Sync, Enhanced Error Handling")
    print("=" * 60)

    if not SDK_AVAILABLE:
        print("\n❌ PYTHON SDK UNAVAILABLE")
        print("   Install with: pip install pan-aisecurity")
        return

    # CREDENTIAL VALIDATION
    print("\n🔑 VALIDATING CREDENTIALS...")

    pan_api_key = os.getenv("PANW_AI_SEC_API_KEY")
    pan_ai_profile_name = os.getenv("PANW_AI_SEC_PROFILE_NAME")

    if not pan_api_key:
        print("❌ ERROR: Missing PANW_AI_SEC_API_KEY environment variable")
        return

    if not pan_ai_profile_name:
        print("❌ ERROR: Missing PANW_AI_SEC_PROFILE_NAME environment variable")
        return

    print("✅ Palo Alto Networks credentials validated")

    # AZURE OPENAI VALIDATION
    azure_project = os.getenv("AZURE_PROJECT")
    azure_key = os.getenv("AZURE_KEY")
    azure_deploy = os.getenv("AZURE_DEPLOY")

    if not all([azure_project, azure_key, azure_deploy]):
        print("❌ ERROR: Missing Azure OpenAI environment variables")
        return

    print("✅ Azure OpenAI credentials validated")

    # INITIALIZE SDK SCANNER
    print("\n🛡️ INITIALIZING PYTHON SDK SCANNER...")

    try:
        scanner = SDKSecurityScanner(
            api_key=pan_api_key,
            profile_name=pan_ai_profile_name,
            num_retries=3
        )
        print("✅ Python SDK Scanner initialized successfully")
        print(f"   API Endpoint: {scanner.config.api_endpoint}")
        print(f"   Profile: {scanner.profile_name}")
        print(f"   Retries: {scanner.config.num_retries}")
    except Exception as e:
        print(f"❌ Failed to initialize SDK Scanner: {e}")
        return

    # INITIALIZE AZURE OPENAI CLIENT
    print("\n🧠 INITIALIZING AZURE OPENAI CLIENT...")

    azure_client = None
    azure_endpoint = f"https://{azure_project}.openai.azure.com/"

    try:
        azure_client = AzureOpenAI(
            azure_endpoint=azure_endpoint,
            api_key=azure_key,
            api_version="2024-02-15-preview",
            http_client=httpx.Client(verify=False, http2=True),
        )
        print("✅ Azure OpenAI client initialized successfully")
    except Exception as e:
        print(f"❌ Failed to initialize Azure OpenAI client: {e}")
        azure_client = None

    # INTERACTIVE CHAT LOOP
    print("\n" + "=" * 60)
    print("PYTHON SDK CHATBOT READY")
    print("=" * 60)
    print("Features:")
    print("• Palo Alto Networks AI Security Python SDK")
    print("• Production-grade threat detection and analysis")
    print("• Async scanning with intelligent retry logic")
    print("• Comprehensive security insights and recommendations")
    print("• Type 'exit' to terminate")

    while True:
        user_input = input("\n👤 You: ").strip()

        if user_input.lower() == 'exit':
            print("\n👋 SDK session terminated. Goodbye!")
            break

        if not user_input:
            print("⚠️  Please enter a non-empty message.")
            continue

        # PYTHON SDK SECURITY SCANNING
        print("\n🔒 PYTHON SDK SECURITY SCANNING")
        print("=" * 50)

        try:
            # Perform async security scan using SDK
            scan_result = await scanner.async_scan(user_input)

            # Display comprehensive results
            scanner.display_enhanced_results(scan_result)

            # SECURITY DECISION PROCESSING
            category = scan_result.get('category')
            action = scan_result.get('action')

            print(f"\n🚦 SECURITY DECISION:")
            print(f"   Classification: {category}")
            print(f"   Recommended Action: {action}")

            if category == "malicious" or action == "block":
                # MESSAGE BLOCKED
                print("\n🚫 MESSAGE BLOCKED BY SDK SECURITY")
                print("=" * 50)
                print(f"Security Status: {category.upper()}")
                print(f"Action Taken: {action.upper()}")
                print(f"Scan Time: {scan_result.get('scan_time_ms', 0):.1f}ms")
                print("\n🤖 SDK Response: This message cannot be processed due to")
                print("   security policy violations detected by the Palo Alto Networks")
                print("   AI Security Python SDK. Please review the detailed threat")
                print("   analysis above and modify your message accordingly.")
                print("=" * 50)

            elif category == "benign" and action == "allow":
                # MESSAGE APPROVED
                print("\n✅ SDK SECURITY CHECK PASSED")
                print("=" * 50)
                print(f"Security Status: {category.upper()}")
                print(f"Action: {action.upper()}")
                print(f"Scan Time: {scan_result.get('scan_time_ms', 0):.1f}ms")
                print("SDK analysis confirms content is safe for AI processing...")
                print("=" * 50)

                # AI PROCESSING
                if azure_client:
                    print("\n🧠 AI PROCESSING PHASE")
                    print("=" * 50)
                    print("Generating AI response...")

                    try:
                        response = azure_client.chat.completions.create(
                            model=azure_deploy,
                            messages=[
                                {
                                    "role": "system",
                                    "content": "You are a helpful, knowledgeable, and professional assistant. You provide accurate, informative responses while maintaining a friendly and supportive tone."
                                },
                                {
                                    "role": "user",
                                    "content": user_input
                                },
                            ],
                            temperature=0.7,
                            max_tokens=800,
                            top_p=0.95,
                            frequency_penalty=0,
                            presence_penalty=0,
                            stop=None
                        )

                        ai_response = response.choices[0].message.content

                        print("\n" + "=" * 60)
                        print("🤖 AI RESPONSE:")
                        print("=" * 60)
                        print(ai_response)
                        print("=" * 60)

                    except Exception as azure_err:
                        print(f"\n❌ AZURE OPENAI ERROR: {azure_err}")
                        print(
                            "🤖 Response: A technical error occurred during AI processing.")
                else:
                    print("\n⚠️  AZURE OPENAI UNAVAILABLE")
                    print(
                        "🤖 Response: Message passed security screening, but AI processing unavailable.")

            else:
                print(f"\n⚠️  UNEXPECTED SECURITY RESULT")
                print(f"   Category: {category}")
                print(f"   Action: {action}")

        except AISecSDKException as sdk_err:
            print(f"\n❌ SDK ERROR: {sdk_err}")
            print("🤖 Response: SDK security scanning encountered an issue.")

        except Exception as general_err:
            print(f"\n❌ UNEXPECTED ERROR: {general_err}")
            print("🤖 Response: An unexpected error occurred during processing.")


if __name__ == "__main__":
    """Python SDK Entry Point"""
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n\n👋 Python SDK chatbot terminated by user. Goodbye!")
    except Exception as e:
        print(f"\n❌ Fatal error: {e}")
        print("Please check your configuration and try again.")
