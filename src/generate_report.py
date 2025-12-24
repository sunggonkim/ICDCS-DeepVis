
from fpdf import FPDF
import os

class UsenixReport(FPDF):
    def header(self):
        self.set_font('times', 'I', 10)
        self.cell(0, 10, 'USENIX Security 2025 Submission - Prototype DeepVis', align='R')
        self.ln(15)

    def footer(self):
        self.set_y(-15)
        self.set_font('times', 'I', 9)
        self.cell(0, 10, f'Page {self.page_no()} | DeepVis: Hash-Based Neural Mapping', align='C')

    def section_title(self, title):
        self.set_font('times', 'B', 14)
        self.ln(5)
        self.cell(0, 10, title, new_x="LMARGIN", new_y="NEXT")
        self.line(10, self.get_y(), 200, self.get_y())
        self.ln(5)

    def sub_section(self, title):
        self.set_font('times', 'B', 12)
        self.cell(0, 8, title, new_x="LMARGIN", new_y="NEXT")

    def body_text(self, text):
        self.set_font('times', '', 11)
        self.multi_cell(0, 5, text)
        self.ln(3)

    def prompt_box(self, content):
        """Draws a box looking like a system prompt or code block."""
        self.set_font('courier', '', 10)
        self.set_fill_color(240, 240, 240)
        self.multi_cell(0, 5, content, fill=True, border=1)
        self.ln(5)

    def add_image_centered(self, img_path, w=160, caption=""):
        if os.path.exists(img_path):
            self.image(img_path, w=w, x=(210-w)/2)
            self.set_font('times', 'I', 10)
            self.cell(0, 8, caption, align='C', new_x="LMARGIN", new_y="NEXT")
            self.ln(5)

def create_usenix_report():
    pdf = UsenixReport()
    pdf.add_page()
    
    # Title
    pdf.set_font('times', 'B', 20)
    pdf.cell(0, 15, 'DeepVis: A Spatially-Invariant Convolutional Autoencoder', align='C', new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 10, 'for Rootkit Detection via Hash-Based File System Visualization', align='C', new_x="LMARGIN", new_y="NEXT")
    pdf.ln(10)
    
    # Abstract
    pdf.set_font('times', 'B', 12)
    pdf.cell(0, 8, 'Abstract', new_x="LMARGIN", new_y="NEXT")
    pdf.set_font('times', '', 11)
    pdf.multi_cell(0, 5, 
        "Traditional Integrity Monitoring relies on digital signatures, which are brittle to legitimate system updates (churn). "
        "We propose DeepVis, a visual anomaly detection framework that converts file system metadata into 2D RGB images. "
        "By utilizing a novel Hash-based Spatial Mapping ($P_{xy} = H(f) \pmod N$) and Semantic Channel Encoding (Entropy), "
        "we solve the 'Shift Problem' inherent in sorting-based approaches. "
        "Evaluated on 6,856 real system files, DeepVis successfully localizes stealthy rootkits (High Entropy) "
        "even when Global MSE metrics fail due to the high noise of legitimate updates."
    )
    pdf.ln(10)

    # 1. Context & Problem (Prompt Style)
    pdf.section_title("1. System Context & Problem Definition")
    pdf.prompt_box(
        "CONTEXT: File System Integrity Monitoring\n"
        "PROBLEM: The 'MSE Paradox'\n"
        "- Legitimate Update (apt upgrade): Modifies ~5,000 files -> High Global MSE (0.048).\n"
        "- Stealthy Rootkit: Modifies ~3 files -> Low Global MSE (0.041).\n"
        "CONSTRAINT: Global thresholds cannot distinguish Attack from Churn.\n"
        "OBJECTIVE: Develop a Local Anomaly Detection mechanism that is Spatially Invariant."
    )
    pdf.body_text(
        "Standard Convolutional Neural Networks (CNNs) require spatial locality. "
        "Naive file system visualization (sorting by name) destroys this locality: inserting a single file 'a.bin' "
        "shifts every subsequent pixel, causing a massive 'False Positive' wave. "
        "DeepVis addresses this via Hash-based Mapping."
    )

    # 2. Methodology (Instruction Style)
    pdf.section_title("2. Proposed Method: DeepVis Architecture")
    
    pdf.sub_section("2.1 Hash-Based Spatial Invariance")
    pdf.prompt_box(
        "INSTRUCTION: Map File(f) to Pixel(x, y)\n"
        "FORMULA: idx = MD5(f.path) % (W * H)\n"
        "         x = idx // W,  y = idx % W\n"
        "RESULT:\n"
        "- Stability: A file always maps to the same (x,y) regardless of neighbors.\n"
        "- Locality: Attacks are confined to 1 pixel (Point Anomaly)."
    )
    
    pdf.sub_section("2.2 Semantic Channel Encoding")
    pdf.body_text("We encode security-critical metadata into RGB channels to provide semantic meaning to anomalies.")
    pdf.prompt_box(
        "CHANNEL MAPPING:\n"
        " [R]ed   : Shannon Entropy (0.0 - 8.0) -> Detects Packed/Encrypted Payloads.\n"
        " [G]reen : Log(File Size)              -> Detects Buffer Overflow / Binary Growth.\n"
        " [B]lue  : Permissions/Risk Score      -> Detects Privilege Escalation (SUID)."
    )

    # 3. Evaluation (Output Style)
    pdf.add_page()
    pdf.section_title("3. Experimental Evaluation")
    
    pdf.sub_section("3.1 Dataset & Setup")
    pdf.body_text(
        "We trained a Convolutional Autoencoder (CAE) on a baseline of 6,856 real files from a Linux environment (/bin, /usr/bin, /etc). "
        "Training data included simulated legitimate updates (churn) to teach the model robustness."
    )

    pdf.sub_section("3.2 Results: Global vs Local")
    pdf.add_image_centered('reconstruction_errors.png', caption="Fig 1. MSE Paradox: Normal Updates (Blue) have higher error than Attacks (Red).")
    
    pdf.body_text(
        "As shown in Fig 1, Global MSE fails. The 'Normal Update' distribution (Blue) is to the right (higher error) of the 'Rootkit' distribution (Red). "
        "A simple threshold based on MSE would either miss the rootkit or flag every update."
    )
    
    pdf.sub_section("3.3 Visual Proof of Detection")
    pdf.add_image_centered('difference_map.png', caption="Fig 2. Difference Map: Red Hot-Spot indicates a High-Entropy Anomaly.")
    
    pdf.body_text(
        "Fig 2 demonstrates the success of DeepVis. While the global error is low, the Hash-based mapping ensures the rootkit is isolated to a single pixel. "
        "The 'Red' color of the hot spot confirms the anomaly is High Entropy (Packed), immediately distinguishing it from benign size changes."
    )

    # 4. Conclusion (Verdict)
    pdf.section_title("4. Conclusion")
    pdf.prompt_box(
        "FINAL VERDICT: SUCCESS\n"
        "CONTRIBUTION 1: Solved the 'Shift Problem' via Spatial Hash Mapping.\n"
        "CONTRIBUTION 2: Overcame the 'MSE Paradox' via Local Difference Maps.\n"
        "CONTRIBUTION 3: Enabled Semantic Analysis via Entropy-Red Encoding.\n"
        "STATUS: Ready for Paper Drafting."
    )

    output_path = "DeepVis_USENIX_Security_Draft.pdf"
    pdf.output(output_path)
    print(f"Report generated: {output_path}")

if __name__ == "__main__":
    create_usenix_report()
