import tkinter as tk
import scapy.all as scapy
from sklearn.ensemble import RandomForestClassifier
import random
import time
from threading import Thread
import numpy as np
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg


class TrafficSimulation:
    def __init__(self):  # Düzeltildi: parantez hatası giderildi
        self.packets = []
        self.model = RandomForestClassifier()

        # Genişletilmiş eğitim verisi
        self.training_data = [
            [1, 20, 80, 0],  # Normal TCP
            [2, 1000, 5000, 0],  # Normal UDP
            [3, 0, 0, 0],  # Normal ICMP
            [1, 23, 80, 1],  # Saldırı TCP
            [2, 8080, 5000, 1],  # Saldırı UDP
            [3, 0, 0, 1],  # Saldırı ICMP
            [1, 25, 80, 0],  # Ek Normal TCP
            [2, 1500, 6000, 0],  # Ek Normal UDP
            [1, 21, 22, 1],  # Ek Saldırı TCP
            [2, 8081, 6001, 1],  # Ek Saldırı UDP
            [3, 0, 0, 0],  # Ek Normal ICMP
            [3, 0, 0, 1]   # Ek Saldırı ICMP
        ]

        self.train_model()
        self.risk_scores = []

    def extract_features(self, packet):
        """Paket özelliklerini çıkarır: tür, kaynak port, hedef port."""
        if packet.haslayer(scapy.TCP):
            return [1, packet[scapy.TCP].sport, packet[scapy.TCP].dport]
        elif packet.haslayer(scapy.UDP):
            return [2, packet[scapy.UDP].sport, packet[scapy.UDP].dport]
        elif packet.haslayer(scapy.ICMP):
            return [3, 0, 0]  # ICMP için port yok
        else:
            return [0, 0, 0]  # Desteklenmeyen paket

    def train_model(self):
        """Risk analiz modeli için RandomForestClassifier'ı eğitir."""
        X_train = np.array([data[:3] for data in self.training_data])
        y_train = np.array([data[3] for data in self.training_data])
        self.model.fit(X_train, y_train)

    def predict_risk(self, packet):
        """Bir paket için risk tahmini yapar."""
        features = self.extract_features(packet)
        prediction = self.model.predict([features])
        return prediction[0]  # 0: düşük risk, 1: yüksek risk

    def start_sniffing(self, update_callback):
        """Gerçek ağ trafiğini yakalar ve risk analizi yapar."""
        def packet_callback(packet):
            self.packets.append(packet)
            risk = self.predict_risk(packet)
            self.risk_scores.append(risk)
            update_callback(packet.summary(), risk)

        scapy.sniff(prn=packet_callback, count=10)  # 10 paket yakala ve analiz et

    def generate_realistic_simulation(self, update_callback):
        """Gerçekçi ağ trafiği simülasyonu yapar."""
        self.packets = []  # Eski simülasyon paketlerini temizle
        self.risk_scores = []

        for i in range(5):
            # TCP paketi simülasyonu
            tcp_packet = scapy.IP(dst=f"192.168.1.{random.randint(1, 255)}")/scapy.TCP(dport=random.randint(20, 80))
            self.packets.append(tcp_packet)
            risk = self.predict_risk(tcp_packet)
            self.risk_scores.append(risk)
            update_callback(f"TCP Paketi Gönderildi: {tcp_packet.summary()} - Risk: {'Yüksek' if risk == 1 else 'Düşük'}", risk)

            # UDP paketi simülasyonu
            udp_packet = scapy.IP(dst=f"192.168.1.{random.randint(1, 255)}")/scapy.UDP(dport=random.randint(1000, 5000))
            self.packets.append(udp_packet)
            risk = self.predict_risk(udp_packet)
            self.risk_scores.append(risk)
            update_callback(f"UDP Paketi Gönderildi: {udp_packet.summary()} - Risk: {'Yüksek' if risk == 1 else 'Düşük'}", risk)

            # ICMP paketi simülasyonu (Ping)
            icmp_packet = scapy.IP(dst=f"192.168.1.{random.randint(1, 255)}")/scapy.ICMP()
            self.packets.append(icmp_packet)
            risk = self.predict_risk(icmp_packet)
            self.risk_scores.append(risk)
            update_callback(f"ICMP Paketi Gönderildi: {icmp_packet.summary()} - Risk: {'Yüksek' if risk == 1 else 'Düşük'}", risk)

            time.sleep(1)  # Simülasyon arası bekle


class NetworkManagementApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Ağ Yönetim Uygulaması")
        self.root.geometry("1200x800")
        self.root.configure(bg='#f0f0f0')  # Daha modern bir arka plan rengi

        self.traffic_simulation = TrafficSimulation()
        self.create_widgets()

    def create_widgets(self):
        self.title_label = tk.Label(self.root, text="Ağ Yönetim Uygulamasına Hoşgeldiniz", font=("Arial", 24), bg='#f0f0f0')
        self.title_label.pack(pady=20)

        self.capture_button = tk.Button(self.root, text="Ağ Trafiği Yakalamaya Başla", command=self.open_capture_window, width=30, height=2, bg='#00BFFF', fg='white', font=("Arial", 14))
        self.capture_button.pack(pady=10)

        self.simulation_button = tk.Button(self.root, text="Ağ Trafiği Simülasyonu Başlat", command=self.open_simulation_window, width=30, height=2, bg='#00BFFF', fg='white', font=("Arial", 14))
        self.simulation_button.pack(pady=10)

        self.risk_analysis_button = tk.Button(self.root, text="Risk Analizini Göster", command=self.show_risk_analysis, width=30, height=2, bg='#FFD700', fg='black', font=("Arial", 14))
        self.risk_analysis_button.pack(pady=10)

        self.exit_button = tk.Button(self.root, text="Çıkış", command=self.root.quit, width=30, height=2, bg='red', fg='white', font=("Arial", 14))
        self.exit_button.pack(pady=10)

        # Risk gösterge grafik alanı
        self.fig, self.ax = plt.subplots(figsize=(5, 4))
        self.canvas = FigureCanvasTkAgg(self.fig, master=self.root)
        self.canvas_widget = self.canvas.get_tk_widget()
        self.canvas_widget.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)

    def open_capture_window(self):
        window = tk.Toplevel(self.root)
        window.title("Ağ Trafiği Yakalama")
        window.geometry("1000x800")
        window.configure(bg='lightgreen')

        capture_label = tk.Label(window, text="Ağ Trafiği Yakalama Başlatıldı...", font=("Arial", 20), bg='lightgreen')
        capture_label.pack(pady=20)

        explanation_label = tk.Label(window, text="Bu pencerede gerçek ağ trafiği yakalanıyor ve analiz ediliyor...", font=("Arial", 14), bg='lightgreen')
        explanation_label.pack(pady=10)

        self.traffic_listbox = tk.Listbox(window, width=50, height=15)
        self.traffic_listbox.pack(pady=10)

        def update_traffic(packet_summary, risk):
            self.traffic_listbox.insert(tk.END, f"{packet_summary} - Risk: {'Yüksek' if risk == 1 else 'Düşük'}")
            self.update_risk_graph()

            # Ağ güvenlik uyarısı
            if risk == 1:
                self.show_alert("Yüksek Risk Tespit Edildi!", f"{packet_summary} yüksek risk taşımaktadır.")

        sniffing_thread = Thread(target=self.traffic_simulation.start_sniffing, args=(update_traffic,))
        sniffing_thread.start()

        close_button = tk.Button(window, text="Kapat", command=window.destroy, width=20, height=2, bg='orange')
        close_button.pack(pady=10)

    def open_simulation_window(self):
        window = tk.Toplevel(self.root)
        window.title("Ağ Trafiği Simülasyonu")
        window.geometry("800x1000")
        window.configure(bg='lightblue')

        simulation_label = tk.Label(window, text="Ağ Trafiği Simülasyonu Başlatıldı...", font=("Arial", 20), bg='lightblue')
        simulation_label.pack(pady=20)

        self.simulation_listbox = tk.Listbox(window, width=50, height=15)
        self.simulation_listbox.pack(pady=10)

        def update_simulation(packet_summary, risk):
            self.simulation_listbox.insert(tk.END, f"{packet_summary} - Risk: {'Yüksek' if risk == 1 else 'Düşük'}")
            self.update_risk_graph()

        simulation_thread = Thread(target=self.traffic_simulation.generate_realistic_simulation, args=(update_simulation,))
        simulation_thread.start()

        close_button = tk.Button(window, text="Kapat", command=window.destroy, width=20, height=2, bg='orange')
        close_button.pack(pady=10)

    def update_risk_graph(self):
        """Risk puanlarını grafik üzerinde günceller."""
        self.ax.clear()
        self.ax.plot(self.traffic_simulation.risk_scores, marker='o', color='blue', label='Risk Skoru')
        self.ax.set_title('Risk Skoru Zamanla')
        self.ax.set_xlabel('Zaman (saniye)')
        self.ax.set_ylabel('Risk Skoru')
        self.ax.set_ylim(-0.5, 1.5)
        self.ax.legend()
        self.canvas.draw()

    def show_alert(self, title, message):
        """Kullanıcıya bir uyarı mesajı gösterir."""
        alert_window = tk.Toplevel(self.root)
        alert_window.title(title)
        alert_window.geometry("1000x800")
        alert_window.configure(bg='red')
        
        alert_label = tk.Label(alert_window, text=message, font=("Arial", 14), bg='red', fg='white')
        alert_label.pack(pady=20)

        ok_button = tk.Button(alert_window, text="Tamam", command=alert_window.destroy, width=10, height=2, bg='orange')
        ok_button.pack(pady=10)

    def show_risk_analysis(self):
        """Risk analiz sonuçlarını gösterir."""
        analysis_window = tk.Toplevel(self.root)
        analysis_window.title("Risk Analizi")
        analysis_window.geometry("800x600")
        analysis_window.configure(bg='lightgrey')

        analysis_label = tk.Label(analysis_window, text="Son Risk Analizleri:", font=("Arial", 18), bg='lightgrey')
        analysis_label.pack(pady=20)

        for score in self.traffic_simulation.risk_scores:
            risk_label = tk.Label(analysis_window, text=f"Risk: {'Yüksek' if score == 1 else 'Düşük'}", font=("Arial", 14), bg='lightgrey')
            risk_label.pack()

        close_button = tk.Button(analysis_window, text="Kapat", command=analysis_window.destroy, width=10, height=2, bg='orange')
        close_button.pack(pady=10)


if __name__ == "__main__":
    root = tk.Tk()
    app = NetworkManagementApp(root)
    root.mainloop()
