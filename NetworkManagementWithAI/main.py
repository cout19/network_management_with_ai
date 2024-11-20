# main.py
import tkinter as tk
from tkinter import PhotoImage, Toplevel, Label
from traffic_capture import TrafficCapture
from traffic_simulation import TrafficSimulation, DynamicRiskAssessment, PredictiveAnalytics
import pandas as pd
import time

class AIResultsWindow(Toplevel):
    def __init__(self, master, y_test, y_pred, risk_level, potential_threats):
        super().__init__(master)
        self.title("AI Results")
        self.geometry("600x400")

        Label(self, text="Model Evaluation Results", font=("Helvetica", 16)).pack(pady=10)
        
        # Display classification report
        report_label = Label(self, text="Classification Report:\n" + str(y_pred))
        report_label.pack(pady=5)

        # Display risk level
        risk_label = Label(self, text="User Risk Level: " + str(risk_level))
        risk_label.pack(pady=5)

        # Display potential threats
        threats_label = Label(self, text="Detected Potential Threats: " + str(potential_threats))
        threats_label.pack(pady=5)

        # Show saved plots
        self.show_plots()

    def show_plots(self):
        # Load images
        report_image = PhotoImage(file='packets_sent_report.png')
        cm_image = PhotoImage(file='confusion_matrix.png')

        # Display the first image
        report_label = Label(self, image=report_image)
        report_label.image = report_image
        report_label.pack(pady=10)

        # Display the second image
        cm_label = Label(self, image=cm_image)
        cm_label.image = cm_image
        cm_label.pack(pady=10)

def main():
    # Start network traffic capture
    print("Starting network traffic capture...")
    capture = TrafficCapture(packet_count=5)  # Capture 5 packets
    capture.start()
    
    # Start network traffic simulation
    print("Starting network traffic simulation...")
    sim = TrafficSimulation()

    # Send packets with different protocols
    target_ip = "192.168.1.1"  # Example target IP
    for _ in range(3):  # Send packets 3 times
        sim.send(target_ip, 80, "TCP")
        sim.send(target_ip, 80, "UDP")
        sim.send(target_ip, None, "ICMP")

    # Create report
    sim.create_report()

    # Data Preprocessing for AI model
    data = sim.preprocess_data()
    
    # Train and test the model
    y_test, y_pred = sim.train_and_test_model(data)

    # Generate confusion matrix
    sim.confusion_matrix(y_test, y_pred)

    # Dynamic Risk Assessment
    risk_assessment = DynamicRiskAssessment()
    # Example user behavior data
    user_data = [0.8, 1, 0.9]  # Placeholder data
    risk_assessment.train_model(data)  # Train the model before assessing risk
    risk_level = risk_assessment.assess_risk(user_data)

    # Predictive Analytics
    predictive_analytics = PredictiveAnalytics()
    user_behavior_data = [0.9, 0.5, 0.6]  # Placeholder user behavior data
    predictive_analytics.monitor_user_behavior(user_behavior_data)
    potential_threats = predictive_analytics.potential_threats
    predictive_analytics.report_threats()

    # Show AI results in a new window
    root = tk.Tk()
    root.withdraw()  # Hide the main window
    ai_results_window = AIResultsWindow(root, y_test, y_pred, risk_level, potential_threats)
    root.mainloop()

if __name__ == "__main__":
    main()
