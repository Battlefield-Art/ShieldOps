"""FastAPI app with ShieldOps SDK middleware.

Demonstrates using ShieldOps to intercept and audit
API requests in a FastAPI application.
"""

from fastapi import FastAPI, Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

from shieldops.sdk.config import SDKConfig, SDKMode
from shieldops.sdk.interceptor import ShieldOpsInterceptor

# Configure SDK
config = SDKConfig(api_key="sk-demo-key", mode=SDKMode.ENFORCE, agent_id="fastapi-demo")
interceptor = ShieldOpsInterceptor(config)


class ShieldOpsMiddleware(BaseHTTPMiddleware):
    """Middleware that intercepts API requests via ShieldOps SDK."""

    async def dispatch(self, request: Request, call_next):
        # Intercept the API call
        tool_name = f"{request.method}:{request.url.path}"
        args = {"method": request.method, "path": str(request.url.path)}

        result = interceptor.intercept(tool_name, args)

        if result.decision == "block":
            return JSONResponse(
                status_code=403,
                content={
                    "error": "Request blocked by ShieldOps Agent Firewall",
                    "risk_score": result.risk_score,
                    "reasons": result.reasons,
                },
            )

        # Record the call
        response = await call_next(request)
        interceptor.record(
            tool_name=tool_name,
            args_hash=ShieldOpsInterceptor.hash_args(args),
            result_summary=f"status:{response.status_code}",
            latency_ms=0,
            decision=result.decision,
            risk_score=result.risk_score,
        )
        return response


# Create app with middleware
app = FastAPI(title="ShieldOps Protected API")
app.add_middleware(ShieldOpsMiddleware)


@app.get("/")
async def root():
    return {"message": "This API is protected by ShieldOps Agent Firewall"}


@app.get("/data")
async def get_data():
    return {"data": [1, 2, 3], "protected": True}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=8080)
