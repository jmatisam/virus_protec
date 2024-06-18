from flask import Flask, render_template, request
from flask_cors import CORS
from virus_total_apis import PublicApi
import requests
import openai
import json

app = Flask(__name__)


# Configura tu clave de API de VirusTotal
API_KEY = '55db50a9b3a3e55ab557ebb72d2b6afd65d54dfc4555fb11900e801d991c68af'
api = PublicApi(API_KEY)

# Clave de API de OpenAI
OPENAI_API_KEY = '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'

# Ruta para el formulario HTML
@app.route('/')
def index():
    return render_template('index.html')

# Ruta para manejar el escaneo de la URL
@app.route('/analizar', methods=['POST'])
def analizar_url():
    if request.method == 'POST':
        # Obtiene la URL del formulario HTML
        url = request.form['url']

        # Realiza el análisis de la URL
        response = enviar_url_para_analisis(url)
        permalink = response['results']['permalink']
    
        # Obtener información de VirusTotal
        resultado = obtener_informacion_virustotal(permalink, API_KEY)

        # Obtener un resumen y recomendaciones de ChatGPT
        resumen_chatgpt = obtener_resumen_chatgpt(resultado, OPENAI_API_KEY)

        # Devolver los resultados a una plantilla HTML
        return render_template('resultado.html', URL = url, resultado=resultado, resumen_chatgpt=resumen_chatgpt)

def enviar_url_para_analisis(url):
    response = api.scan_url(url)
    return response

def obtener_informacion_virustotal(url, api_key):
    # Obtener el ID de la URL
    url_base = url.split('/')[-3]
    # Construir la segunda URL utilizando el ID extraído
    url_api_virustotal = f'https://www.virustotal.com/api/v3/urls/{url_base}'

    # Headers con la clave de la API
    headers = {
        'x-apikey': api_key
    }

    try:
        # Realizar la solicitud GET a la URL de VirusTotal
        response = requests.get(url_api_virustotal, headers=headers)
        response.raise_for_status()  # Levantar una excepción para errores HTTP

        # Si la solicitud fue exitosa, procesar la respuesta
        data = response.json()
        analysis_stats = data["data"]["attributes"]["last_analysis_stats"]
        return analysis_stats
    except requests.exceptions.RequestException as e:
        # Capturar y manejar cualquier error de solicitud
        print("Error al realizar la solicitud a VirusTotal:", e)
        return None

def obtener_resumen_chatgpt(resultado, OPENAI_API_KEY):
    # Convertir los resultados a un formato de texto
    texto_resultado = f"Actúa como un experto en ciberseguridad al que se le pasa los resultados del análisis de una página web utilizando VirusTotal. Por ejemplo, si hay 2 resultados 'maliciosos' y 0 'sospechosos',esto indica el número de antivirus que han detectado cada categoría.comienza saludando y presentandote como Portal Virus Protec, luego analiza cada categoria quye te paso en el json y le resumen los posibles peligros y das un consejo. Ajusta el mensaje a 300 tokens como máximo. A continuación, te proporciono el análisis de VirusTotal:Resultado de su análisis:\n{json.dumps(resultado, indent=2)}"
   
    # Inicializar el cliente de OpenAI
    openai.api_key = OPENAI_API_KEY
    
    # Obtener un resumen y recomendaciones de ChatGPT
    prompt = texto_resultado

    salida = openai.completions.create(
        model="gpt-3.5-turbo-instruct",
        prompt=prompt,
        max_tokens=410
    )
        
    # Obtener el texto del resumen generado por ChatGPT
    resumen_texto = salida.choices[0].text
    return resumen_texto

if __name__ == '__main__':
    app.run(debug=True)
