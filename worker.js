const allowedIpAddress = '123.45.67.89';

addEventListener("fetch", (event) => {
  event.respondWith(handleRequest(event.request));
});

async function handleRequest(request) {
  // Check if the request comes from the allowed IP address
  const requestIpAddress = request.headers.get("CF-Connecting-IP");
  if (requestIpAddress !== allowedIpAddress) {
    return new Response("Forbidden", { status: 403 });
  }

  try {
    const requestData = await request.json();

    const proxiedRequest = new Request(requestData.url, {
      method: requestData.method,
      headers: requestData.headers,
      body: requestData.body ? atob(requestData.body) : null,
    });

    const response = await fetch(proxiedRequest);
    const responseBody = await response.arrayBuffer();

    const responseInit = {
      status: response.status,
      statusText: response.statusText,
      headers: Object.fromEntries(response.headers.entries()),
    };

    const responseData = {
      status: response.status,
      statusText: response.statusText,
      headers: responseInit.headers,
      body: btoa(String.fromCharCode(...new Uint8Array(responseBody))),
    };

    return new Response(JSON.stringify(responseData), {
      headers: { "Content-Type": "application/json" },
    });
  } catch (error) {
    return new Response(JSON.stringify({ error: error.message }), { status: 500 });
  }
}
