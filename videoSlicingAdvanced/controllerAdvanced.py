from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, udp
from ryu.ofproto import ether as ether_types
import json
import time
from ryu.lib import hub
import requests


class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.datapaths = {}
        self.flow_stats = {}
        self.FLASK_SERVER_URL = 'http://127.0.0.1:5000/update_stats'
        self.monitor_thread = hub.spawn(self._monitor)

        ### MODIFICA: Aggiunti per la classificazione dinamica
        # 1. Traccia lo stato attuale di ogni flusso ('normal' o 'video')
        self.flow_path_state = {}
        # 2. Soglia in Kbps per considerare un flusso come "video" (es. 5 Mbps)
        self.VIDEO_BANDWIDTH_THRESHOLD_KBPS = 500

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        self.datapaths[datapath.id] = datapath

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    ### MODIFICA: Aggiunto il parametro 'command' per poter MODIFICARE i flussi
    def add_flow(self, datapath, priority, match, actions, buffer_id=None, command=ofproto_v1_3.OFPFC_ADD):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id is not None:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst, command=command) # command aggiunto
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst, command=command) # command aggiunto
        datapath.send_msg(mod)

    def _monitor(self):
        while True:
            for dp in self.datapaths.values():
                self._request_flow_stats(dp)
            hub.sleep(1)

    def _request_flow_stats(self, datapath):
        parser = datapath.ofproto_parser
        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        dpid = ev.msg.datapath.id
        datapath = ev.msg.datapath
        ### MODIFICA: Aggiunti parser e ofproto per poter modificare i flussi da qui
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        current_time = time.time()
        body = ev.msg.body

        stats_to_send = []

        for stat in body:
            if stat.priority != 10:
                continue

            match = stat.match
            src = match.get('eth_src')
            dst = match.get('eth_dst')
            # ... le altre variabili sono già qui
            byte_count = stat.byte_count

            if not src or not dst:
                continue

            key = (dpid, src, dst, match.get('eth_type'), match.get('ip_proto'), match.get('udp_dst'))
            last = self.flow_stats.get(key)
            bandwidth_kbps = 0
            if last:
                time_diff = current_time - last['time']
                if time_diff > 0:
                    delta_bytes = byte_count - last['bytes']
                    bandwidth_kbps = (delta_bytes * 8) / (time_diff * 1000)

            self.flow_stats[key] = {'bytes': byte_count, 'time': current_time}

            ### MODIFICA: Aggiunta la logica di classificazione e modifica dei flussi
            current_state = self.flow_path_state.get(key, 'normal')
            
            # Se la banda supera la soglia e il flusso è 'normal', lo promuoviamo a 'video'
            if bandwidth_kbps > self.VIDEO_BANDWIDTH_THRESHOLD_KBPS and current_state == 'normal':
                self.logger.info(f"[DPID {dpid}] PROMUOVO flusso {src}->{dst} a 'video' (Banda: {bandwidth_kbps:.2f} Kbps)")
                # La logica di routing è richiamata qui, specificando che è traffico video
                out_port = self._get_forwarding_path(dpid, src, dst, is_video_traffic=True)
                if out_port:
                    actions = [parser.OFPActionOutput(p) for p in out_port]
                    self.add_flow(datapath, 10, match, actions, command=ofproto.OFPFC_MODIFY_STRICT)
                self.flow_path_state[key] = 'video'
            
            # Se la banda scende sotto la soglia e il flusso era 'video', lo retrocediamo a 'normal'
            elif bandwidth_kbps < self.VIDEO_BANDWIDTH_THRESHOLD_KBPS and current_state == 'video':
                self.logger.info(f"[DPID {dpid}] RETROCEDO flusso {src}->{dst} a 'normal' (Banda: {bandwidth_kbps:.2f} Kbps)")
                out_port = self._get_forwarding_path(dpid, src, dst, is_video_traffic=False)
                if out_port:
                    actions = [parser.OFPActionOutput(p) for p in out_port]
                    self.add_flow(datapath, 10, match, actions, command=ofproto.OFPFC_MODIFY_STRICT)
                self.flow_path_state[key] = 'normal'

            stat_entry = {
                'dpid': dpid, 'src': src, 'dst': dst,
                'bandwidth_kbps': round(max(0, bandwidth_kbps), 2),
                'path_state': self.flow_path_state.get(key, 'unknown'), # Invia lo stato corrente
                'eth_type': match.get('eth_type'),
                'ip_proto': match.get('ip_proto'),
                'udp_dst': match.get('udp_dst')
            }
            stats_to_send.append(stat_entry)

        if stats_to_send:
            hub.spawn(self._send_stats_to_flask, stats_to_send)

    def _send_stats_to_flask(self, stats):
        try:
            requests.post(self.FLASK_SERVER_URL, data=json.dumps(stats),
                          headers={'Content-Type': 'application/json'})
        except requests.exceptions.RequestException as e:
            self.logger.error("Errore nell'invio delle statistiche al server: %s", e)

    ### MODIFICA: La logica di routing è stata estratta in una funzione separata
    # per evitare duplicazione di codice e renderla riutilizzabile.
    def _get_forwarding_path(self, dpid, src, dst, in_port=None, is_video_traffic=False):
        """Questa funzione contiene la TUA logica di routing originale."""
        out_port = []
        H1 = "00:00:00:00:00:01"
        H2 = "00:00:00:00:00:02"
        H3 = "00:00:00:00:00:03"
        H4 = "00:00:00:00:00:04"

        # Tutta la tua logica if/elif/else è qui, intatta.
        if dpid == 1:
            if src == H1:
                if is_video_traffic:
                    if dst == H3 or dst == H4: out_port.append(3)
                    elif dst == H2: out_port.append(2)
                    else: out_port.extend([2, 3])
                else:
                    if dst == H3 or dst == H4: out_port.append(4)
                    elif dst == H2: out_port.append(2)
                    else: out_port.extend([2, 4])
            elif src == H2:
                if is_video_traffic:
                    if dst == H3 or dst == H4: out_port.append(3)
                    elif dst == H1: out_port.append(1)
                    else: out_port.extend([1, 3])
                else:
                    if dst == H3 or dst == H4: out_port.append(4)
                    elif dst == H1: out_port.append(1)
                    else: out_port.extend([1, 4])
            elif src == H3 or src == H4:
                if dst == H1: out_port.append(1)
                elif dst == H2: out_port.append(2)
                else: out_port.extend([1, 2])
        elif dpid == 2 and in_port:
            out_port.append(2 if in_port == 1 else 1)
        elif dpid == 3 and in_port:
            out_port.append(2 if in_port == 1 else 1)
        elif dpid == 4:
            if src == H3:
                if is_video_traffic:
                    if dst in (H1, H2): out_port.append(1)
                    elif dst == H4: out_port.append(4)
                    else: out_port.extend([1, 4])
                else:
                    if dst in (H1, H2): out_port.append(2)
                    elif dst == H4: out_port.append(4)
                    else: out_port.extend([2, 4])
            elif src == H4:
                if is_video_traffic:
                    if dst in (H1, H2): out_port.append(1)
                    elif dst == H3: out_port.append(3)
                    else: out_port.extend([1, 3])
                else:
                    if dst in (H1, H2): out_port.append(2)
                    elif dst == H3: out_port.append(3)
                    else: out_port.extend([2, 3])
            elif src in (H1, H2):
                if dst == H3: out_port.append(3)
                elif dst == H4: out_port.append(4)
                else: out_port.extend([3, 4])
        return out_port

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofp = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        dpid = datapath.id

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        eth_type = eth.ethertype
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        src = eth.src
        dst = eth.dst
        
        ### MODIFICA: Semplificazione radicale di questa sezione.
        # 1. Non proviamo più a indovinare se il traffico è video qui.
        # 2. Tutti i nuovi flussi sono considerati 'normal' di default.
        out_port = self._get_forwarding_path(dpid, src, dst, in_port, is_video_traffic=False)
        if not out_port:
            self.logger.info(f"Nessun percorso trovato per {src}->{dst} in DPID {dpid}")
            return
            
        actions = [parser.OFPActionOutput(p) for p in out_port]

        # La tua logica di creazione del match è corretta e la manteniamo
        match = None
        if eth_type == ether_types.ETH_TYPE_IP:
            ip_pkt = pkt.get_protocol(ipv4.ipv4)
            if ip_pkt.proto == 17:
                udp_pkt = pkt.get_protocol(udp.udp)
                match = parser.OFPMatch(in_port=in_port, eth_src=src, eth_dst=dst,
                                        eth_type=ether_types.ETH_TYPE_IP, ip_proto=17,
                                        udp_dst=udp_pkt.dst_port)
            else:
                match = parser.OFPMatch(in_port=in_port, eth_src=src, eth_dst=dst,
                                        eth_type=ether_types.ETH_TYPE_IP, ip_proto=ip_pkt.proto)
        else:
            match = parser.OFPMatch(in_port=in_port, eth_src=src, eth_dst=dst, eth_type=eth_type)

        ### MODIFICA: Registriamo il nuovo flusso come 'normal'.
        if match:
            key = (dpid, src, dst, match.get('eth_type'), match.get('ip_proto'), match.get('udp_dst'))
            if key not in self.flow_path_state:
                self.logger.info(f"[DPID {dpid}] Nuovo flusso {src}->{dst}. Instradato su percorso 'normal'.")
                self.flow_path_state[key] = 'normal'

        # Installiamo la regola di flusso iniziale
        if msg.buffer_id != ofp.OFP_NO_BUFFER:
            self.add_flow(datapath, 10, match, actions, msg.buffer_id)
            return
        else:
            self.add_flow(datapath, 10, match, actions)

        # Invia il pacchetto
        data = None
        if msg.buffer_id == ofp.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath,
                                  buffer_id=msg.buffer_id,
                                  in_port=in_port,
                                  actions=actions,
                                  data=data)
        datapath.send_msg(out)
