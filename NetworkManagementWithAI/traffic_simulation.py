from scapy.all import IP, TCP, UDP, ICMP, send
import matplotlib.pyplot as plt
import pandas as pd
from sklearn.preprocessing import MinMaxScaler
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix
import seaborn as sns
import numpy as np

class TrafficSimulation:
    def __init__(self):
        self.sent_packets = []  # To store sent packet information
        self.packet_count = {"TCP": 0, "UDP": 0, "ICMP": 0}  # Packet count by protocol

    def send(self, target_ip, target_port, proto):
        if proto == "TCP":
            self.send_tcp_syn(target_ip, target_port)
        elif proto == "UDP":
            self.send_udp(target_ip, target_port)
        elif proto == "ICMP":
            self.send_icmp(target_ip)

    def send_tcp_syn(self, target_ip, target_port):
        ip_layer = IP(dst=target_ip)
        tcp_layer = TCP(dport=target_port, flags='S')
        packet = ip_layer / tcp_layer
        send(packet)
        self.sent_packets.append((target_ip, target_port, "TCP"))
        self.packet_count["TCP"] += 1

    def send_udp(self, target_ip, target_port):
        ip_layer = IP(dst=target_ip)
        udp_layer = UDP(dport=target_port)
        packet = ip_layer / udp_layer
        send(packet)
        self.sent_packets.append((target_ip, target_port, "UDP"))
        self.packet_count["UDP"] += 1

    def send_icmp(self, target_ip):
        ip_layer = IP(dst=target_ip)
        icmp_layer = ICMP()
        packet = ip_layer / icmp_layer
        send(packet)
        self.sent_packets.append((target_ip, None, "ICMP"))
        self.packet_count["ICMP"] += 1

    def create_report(self):
        # Create a graph based on protocol
        plt.figure(figsize=(10, 6))
        plt.bar(self.packet_count.keys(), self.packet_count.values(), color='skyblue', edgecolor='black')
        plt.title('Number of Packets Sent (By Protocol)')
        plt.xlabel('Protocols')
        plt.ylabel('Number of Packets Sent')
        plt.tight_layout()
        plt.savefig('packets_sent_report.png')  # Save the figure
        plt.show()

    def preprocess_data(self):
        # Create a DataFrame for collected data
        data = {
            'User_Behavior': [0.1, 0.2, 0.3],
            'Device_Info': [0.4, 0.5, 0.6],
            'Contextual_Data': [0.7, 0.8, 0.9],
            'Risk_Level': ['Normal', 'Normal', 'Malicious']  # Example labels
        }
        df = pd.DataFrame(data)

        # Normalize the data
        scaler = MinMaxScaler()
        df[['User_Behavior', 'Device_Info', 'Contextual_Data']] = scaler.fit_transform(df[['User_Behavior', 'Device_Info', 'Contextual_Data']])

        return df

    def train_and_test_model(self, df):
        # Split features and labels
        X = df[['User_Behavior', 'Device_Info', 'Contextual_Data']]
        y = df['Risk_Level']

        # Split data into training and testing sets
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

        # Create model
        model = RandomForestClassifier(n_estimators=100)

        # Train the model
        model.fit(X_train, y_train)

        # Test the model
        y_pred = model.predict(X_test)

        # Evaluate results
        print(classification_report(y_test, y_pred))
        return y_test, y_pred

    def confusion_matrix(self, y_test, y_pred):
        # Create confusion matrix
        cm = confusion_matrix(y_test, y_pred)

        # Visualize confusion matrix
        plt.figure(figsize=(8, 6))
        sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', xticklabels=['Normal', 'Malicious'], yticklabels=['Normal', 'Malicious'])
        plt.ylabel('Actual')
        plt.xlabel('Predicted')
        plt.title('Confusion Matrix')
        plt.savefig('confusion_matrix.png')  # Save the figure
        plt.show()

class DynamicRiskAssessment:
    def __init__(self):
        self.model = RandomForestClassifier()

    def train_model(self, data):
        X = data[['User_Behavior', 'Device_Info', 'Contextual_Data']]
        y = data['Risk_Level']
        self.model.fit(X, y)

    def assess_risk(self, user_data):
        # Check if model is fitted
        if not hasattr(self.model, "estimators_"):
            raise Exception("Model has not been trained. Please call train_model first.")
        risk_level = self.model.predict([user_data])
        return risk_level

    def anomaly_detection(self, user_data, threshold=0.7):
        # Anomaly detection
        if np.mean(user_data) > threshold:
            return True  # Anomalous behavior detected
        return False  # Normal behavior

class PredictiveAnalytics:
    def __init__(self):
        self.potential_threats = []

    def monitor_user_behavior(self, user_data):
        # Monitor user behavior
        threshold = 0.7  # Anomaly threshold
        if self.anomaly_detection(user_data, threshold):
            self.potential_threats.append(user_data)

    def report_threats(self):
        if self.potential_threats:
            print("Detected potential threats:", self.potential_threats)

    def anomaly_detection(self, user_data, threshold=0.7):
        # Anomaly detection
        if np.mean(user_data) > threshold:
            return True  # Anomalous behavior detected
        return False  # Normal behavior
