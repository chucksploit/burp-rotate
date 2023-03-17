from burp import IBurpExtender, IHttpListener, IExtensionStateListener
import json
import base64
import requests

CLOUDFLARE_WORKER_URL = "https://your-worker.your-account.workers.dev"

class BurpExtender(IBurpExtender, IHttpListener, IExtensionStateListener):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()

        callbacks.setExtensionName("Cloudflare Worker Tunnel")
        callbacks.registerHttpListener(self)
        callbacks.registerExtensionStateListener(self)

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if not messageIsRequest:
            return

        request = messageInfo.getRequest()
        request_info = self._helpers.analyzeRequest(request)
        headers = request_info.getHeaders()
        body = request[request_info.getBodyOffset():]

        cloudflare_request = {
            "method": request_info.getMethod(),
            "url": str(request_info.getUrl()),
            "headers": {str(header.split(": ")[0]): str(header.split(": ")[1]) for header in headers if ": " in header},
            "body": base64.b64encode(body).decode('utf-8'),
        }

        response = requests.post(CLOUDFLARE_WORKER_URL, json=cloudflare_request)
        if response.status_code != 200:
            return

        response_data = response.json()
        response_headers = response_data.get("headers", [])
        response_body = base64.b64decode(response_data.get("body", ""))

        response_headers = [header for header in response_headers.items()]
        response_headers.insert(0, f"HTTP/1.1 {response_data['status']} {response_data['statusText']}")

        messageInfo.setResponse(self._helpers.buildHttpMessage(response_headers, response_body))

    def extensionUnloaded(self):
        pass
