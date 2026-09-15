from fastapi import FastAPI
from processor import process_alert
from seed_data import get_sample_alerts

app = FastAPI(
    title="D2 Threat Intelligence Correlation API",
    description="Backend API for alert prioritisation and threat intelligence processing.",
    version="1.0.0"
)


@app.get("/")
def root():
    return {
        "message": "D2 Threat Intelligence Backend is running",
        "status": "ok"
    }


@app.get("/alerts")
def get_alerts():
    alerts = get_sample_alerts()
    processed_alerts = [process_alert(alert) for alert in alerts]

    return {
        "count": len(processed_alerts),
        "alerts": processed_alerts
    }


@app.post("/alerts/process")
def process_single_alert(alert: dict):
    processed_alert = process_alert(alert)

    return {
        "alert": processed_alert
    }


@app.get("/health")
def health_check():
    return {
        "status": "healthy"
    }
