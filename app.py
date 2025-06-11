# app.py
import os
import traceback
from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
from dotenv import load_dotenv
import openai
from analyzer import analyze_pcap

load_dotenv()
openai.api_key = os.getenv("OPENAI_API_KEY")

app = Flask(__name__)
CORS(app)
UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

@app.route("/", methods=["GET"])
def index():
    return render_template("index.html")

@app.route("/upload", methods=["POST"])
def upload_file():
    try:
        if 'file' not in request.files:
            return jsonify({"error": "No file uploaded"}), 400

        file = request.files['file']
        filepath = os.path.join(UPLOAD_FOLDER, file.filename)
        file.save(filepath)

        results = analyze_pcap(filepath)
        alerts = results['alerts']

        if alerts:
            prompt = "\n".join([f"{r['type']} saldırısı tespit edildi. Kaynak: {r['src_ip']} → Hedef: {r['dst_ip']}. Açıklama: {r['description']}" for r in alerts])
            completion = openai.ChatCompletion.create(
                model="gpt-3.5-turbo",
                messages=[
                    {"role": "system", "content": "You are a helpful cybersecurity assistant. Respond in clear and short Turkish."},
                    {"role": "user", "content": f"Aşağıdaki trafik analizine göre kullanıcıya sade bir şekilde açıkla:\n{prompt}\n\nLütfen kısa ve net bir açıklama yap."}
                ]
            )
            commentary = completion.choices[0].message['content']
            return jsonify({
                "file": filepath,
                "total_packets": results['total_packets'],
                "alerts": alerts,
                "llm_commentary": commentary
            })
        else:
            completion = openai.ChatCompletion.create(
                model="gpt-3.5-turbo",
                messages=[
                    {"role": "system", "content": "You are a helpful cybersecurity assistant. Respond only with this exact sentence in Turkish: 'PCAP analizi sonucunda herhangi bir anormallik veya saldırı tespit edilmedi. Sistem güvenli görünüyor.'"},
                    {"role": "user", "content": "PCAP analizinde saldırı bulunamadı. Yukarıdaki ifadeyi sadece aynen döndür."}
                ]
            )
            commentary = completion.choices[0].message['content']
            return jsonify({
                "file": filepath,
                "total_packets": results['total_packets'],
                "alerts": [],
                "llm_commentary": commentary
            })

    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)
