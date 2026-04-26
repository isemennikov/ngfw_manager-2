FROM python:3.11-slim

WORKDIR /app

# РЈСЃС‚Р°РЅРѕРІРєР° СЃРёСЃС‚РµРјРЅС‹С… СѓС‚РёР»РёС‚
RUN apt-get update && apt-get install -y gcc libpq-dev openssl && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Р“РµРЅРµСЂРёСЂСѓРµРј СЃРµСЂС‚РёС„РёРєР°С‚
RUN openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes -subj "/C=RU/ST=Moscow/L=Moscow/O=NGFW Manager/CN=localhost"

# --- Р’РћРў Р­РўРђ РЎРўР РћРљРђ Р Р•РЁРђР•Рў РџР РћР‘Р›Р•РњРЈ ---
ENV PYTHONPATH=/app

COPY . .

CMD ["python", "app/main.py"]
