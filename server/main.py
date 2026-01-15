from fastapi import FastAPI, HTTPException, Query
from typing import List, Optional
from confidential_verifier.sdk import TeeVerifier
from confidential_verifier.types import AttestationReport, VerificationResult

app = FastAPI(title="Confidential Service Verifier API")
verifier = TeeVerifier()


@app.get("/providers")
def list_providers():
    return verifier.list_providers()


@app.get("/models")
async def list_models(provider: str):
    try:
        models = await verifier.list_models(provider)
        return models
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/fetch-report")
async def fetch_report(provider: str, model_id: str):
    try:
        report = await verifier.fetch_report(provider, model_id)
        return report
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/verify")
async def verify_report(report: AttestationReport):
    try:
        result = await verifier.verify(report)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/verify-model")
async def verify_model(provider: str, model_id: str):
    try:
        result = await verifier.verify_model(provider, model_id)
        return result
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
