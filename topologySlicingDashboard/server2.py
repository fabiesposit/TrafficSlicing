from flask import Flask, request, jsonify, render_template
import time

app = Flask(__name__)

# Struttura: {(dpid, src, dst): {'bandwidth_kbps': ..., 'last_updated': ...}}
flow_stats = {}

@app.route('/update_stats', methods=['POST'])
def update_stats():
    stats_list = request.get_json()

    for stat in stats_list:
        key = (stat['dpid'], stat['src'], stat['dst'])

        flow_stats[key] = {
            'bandwidth_kbps': stat['bandwidth_kbps'],
            'last_updated': time.strftime('%H:%M:%S')
        }

    return 'Dati aggiornati', 204

@app.route('/')
def index():
    return render_template('table.html')

@app.route('/flow_data')
def flow_data():
    # Converte i dati in formato JSON leggibile per JS
    response = []
    for (dpid, src, dst), info in flow_stats.items():
        response.append({
            'switch': f'Switch {dpid}',
            'src': src,
            'dst': dst,
            'bandwidth_kbps': info['bandwidth_kbps'],
            'last_updated': info['last_updated']
        })
    return jsonify(response)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
