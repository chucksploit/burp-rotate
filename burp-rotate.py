from burp import IBurpExtender, IHttpListener
import boto3
import time

AWS_ACCESS_KEY_ID = "YOUR_AWS_ACCESS_KEY_ID"
AWS_SECRET_ACCESS_KEY = "YOUR_AWS_SECRET_ACCESS_KEY"
REGION_NAME = "YOUR_REGION_NAME"
DOMAIN_NAME = "YOUR_CUSTOM_DOMAIN_NAME"

class BurpExtender(IBurpExtender, IHttpListener):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()

        callbacks.setExtensionName("AWS IP Rotator")
        callbacks.registerHttpListener(self)

        self.request_count = 0
        self.base_path_mappings = []

        self.init_aws_api_gateway()

    def processHttpMessage(self, toolFlag, messageIsRequest, currentRequest):
        if not messageIsRequest:
            return

        self.request_count += 1

        if self.request_count >= 10:
            self.rotate_ip()
            self.request_count = 0

    def init_aws_api_gateway(self):
        self.session = boto3.Session(
            aws_access_key_id=AWS_ACCESS_KEY_ID,
            aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
            region_name=REGION_NAME
        )

        self.api_gateway_client = self.session.client("apigateway")

        # Retrieve base path mappings for the custom domain
        response = self.api_gateway_client.get_base_path_mappings(
            domainName=DOMAIN_NAME
        )

        self.base_path_mappings = response["items"]

    def rotate_ip(self):
        # Rotate base path mappings
        self.base_path_mappings = self.base_path_mappings[-1:] + self.base_path_mappings[:-1]

        # Update the API Gateway with the rotated base path mappings
        for index, mapping in enumerate(self.base_path_mappings):
            self.api_gateway_client.update_base_path_mapping(
                domainName=DOMAIN_NAME,
                basePath=mapping["basePath"],
                patchOperations=[{
                    "op": "replace",
                    "path": "/restApiId",
                    "value": mapping["restApiId"]
                }]
            )

        # Sleep to allow the changes to propagate
        time.sleep(5)